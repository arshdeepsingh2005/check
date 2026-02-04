"""
Main Flask application factory.
"""
from pathlib import Path

from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO

from app.config import Config
from app.database import SessionLocal, init_db
from app.models import ExchangeRate, User
from app.services import get_cache_service, get_user_auth_service, init_cache_service, init_user_auth_service, user_service, user_sync_worker
from sqlalchemy import func, select

# Auto-detect async mode:
# - Use 'eventlet' for production (Gunicorn with eventlet workers)
# - Use 'threading' for local development
# - Allow override via SOCKETIO_ASYNC_MODE env var
import os

# Check if we're running in production (Gunicorn or Render)
# Render sets PORT env var, Gunicorn sets GUNICORN_CMD_ARGS
is_production = (
    os.environ.get('GUNICORN_CMD_ARGS') is not None or 
    os.environ.get('SERVER_SOFTWARE', '').startswith('gunicorn') or
    os.environ.get('PORT') is not None  # Render sets this
)

# Default async mode based on environment
if os.environ.get('SOCKETIO_ASYNC_MODE'):
    # Explicit override
    async_mode = os.environ.get('SOCKETIO_ASYNC_MODE')
elif is_production:
    # Production: use eventlet (required for Gunicorn eventlet workers)
    async_mode = 'eventlet'
else:
    # Local development: use threading (works without eventlet)
    async_mode = 'threading'

socketio = SocketIO(cors_allowed_origins=Config.ALLOWED_ORIGINS, async_mode=async_mode)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR.parent / "templates"


def create_app(config_class=Config):
    """Create and configure the Flask application."""
    app = Flask(__name__, template_folder=str(TEMPLATE_DIR))
    app.config.from_object(config_class)
    
    CORS(app, origins=config_class.ALLOWED_ORIGINS, supports_credentials=True)
    
    # Initialize SocketIO
    socketio.init_app(app)
    
    # Register blueprints
    from app.routes.main import main_bp
    from app.routes.api import api_bp
    from app.routes.internal import internal_bp
    from app.routes.websocket_routes import ws_bp
    from app.routes.sse_routes import sse_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(internal_bp)
    app.register_blueprint(ws_bp)
    app.register_blueprint(sse_bp)

    # Initialize persistence + service layer
    # Do this synchronously but quickly - database init is fast, user service uses background thread
    import logging
    
    try:
        with app.app_context():
            init_db()
            user_service.start()
            init_cache_service(config_class)
            init_user_auth_service(config_class)
            user_sync_worker.start()
            _preload_pinned_users_to_redis()
            _preload_exchange_rates_to_redis()
    except Exception as e:
        logging.error(f"Error during database/service initialization: {e}", exc_info=True)
    
    _start_sse_cleanup_thread()
    
    return app


def _preload_pinned_users_to_redis():
    """Preload pinned users into Redis for fast WebSocket connections."""
    auth_service = get_user_auth_service()
    if not auth_service or not auth_service.is_available():
        return
    
    try:
        with SessionLocal() as session:
            for username in Config.PINNED_USERS:
                row = session.execute(
                    select(User).where(func.lower(User.username) == username.lower())
                ).scalar_one_or_none()
                
                if row:
                    auth_service.set_user(row.username, row.id)
    except Exception:
        pass


def _preload_exchange_rates_to_redis():
    """Preload all exchange rates into Redis cache on startup."""
    import logging
    logger = logging.getLogger(__name__)
    
    cache_service = get_cache_service()
    if not cache_service:
        logger.warning("Cache service not initialized. Cannot preload exchange rates.")
        return
    
    if not cache_service.is_available():
        logger.warning("Cache service not available (Redis not connected). Cannot preload exchange rates.")
        return
    
    try:
        with SessionLocal() as session:
            # Use scalars() to get ExchangeRate instances directly
            rows = session.execute(select(ExchangeRate)).scalars().all()
            logger.info(f"Found {len(rows)} exchange rate records in database")
            
            exchange_rates = []
            for row in rows:
                if not row.target_currency or not row.rate_from_usd or row.rate_from_usd <= 0:
                    continue
                
                currency = row.target_currency.strip().upper()
                if currency:
                    exchange_rates.append({
                        'currency': currency,
                        'rate': float(row.rate_from_usd)
                    })
            
            logger.info(f"Preparing to preload {len(exchange_rates)} exchange rates to Redis")
            
            logger.info(f"Preparing to preload {len(exchange_rates)} exchange rates to Redis")
            
            if exchange_rates:
                count = cache_service.preload_all_rates(exchange_rates)
                if count > 0:
                    logger.info(f"Successfully preloaded {count} exchange rates to Redis")
                else:
                    logger.warning("preload_all_rates returned 0 - no rates were cached")
            else:
                logger.warning("No valid exchange rates found to preload")
                
    except Exception as e:
        logger.error(f"Error preloading exchange rates to Redis: {e}", exc_info=True)


def _start_sse_cleanup_thread():
    """Start background thread to clean up stale SSE connections."""
    import threading
    import time
    import logging
    
    def cleanup_loop():
        """Background loop to clean up stale SSE connections."""
        from app.sse_manager import sse_manager
        
        while True:
            try:
                time.sleep(60)  # Run every minute
                sse_manager.cleanup_stale_connections(timeout_seconds=120)
            except Exception as e:
                logging.error(f"Error in SSE cleanup loop: {e}")
    
    cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True, name="SSE-Cleanup")
    cleanup_thread.start()


