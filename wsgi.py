"""
WSGI entry point for production.
"""
import sys
import logging

# Configure logging to stdout (Render captures this)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

try:
    from app import create_app, socketio
    app = create_app()
    
    @app.before_request
    def before_request():
        """Execute before each request."""
        pass
    
except Exception as e:
    logger.error("=" * 60)
    logger.error("FATAL ERROR: Failed to create application")
    logger.error("=" * 60)
    logger.error(f"Error: {e}", exc_info=True)
    logger.error("=" * 60)
    # Re-raise so Gunicorn sees the error
    raise


if __name__ == "__main__":
    import os
    PORT = int(os.environ.get("PORT", 5000))
    # Use environment variable for debug mode, default to False for production
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    socketio.run(app, host="0.0.0.0", port=PORT, debug=DEBUG)

