"""
Application configuration.
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # WebSocket configuration
    # Auto-detected in app/__init__.py - 'threading' for dev, 'eventlet' for production
    SOCKETIO_ASYNC_MODE = os.environ.get('SOCKETIO_ASYNC_MODE', 'threading')  # Default to threading for local dev
    SOCKETIO_CORS_ALLOWED_ORIGINS = '*'
    
    # Code ingestion settings
    MAX_CODE_LENGTH = 1000
    CODE_QUEUE_SIZE = 1000
    INGEST_SHARED_TOKEN = os.environ.get('INGEST_SHARED_TOKEN')
    
    # SSE configuration
    WS_SECRET = os.environ.get('WS_SECRET') or os.environ.get('SECRET_KEY') or 'dev-ws-secret-change-in-production'
    
    # Allowed origins for CORS and embed-stream
    ALLOWED_ORIGINS = [
        "https://kciade.online",
        "https://www.kciade.online",
        "http://kciade.online",
        "http://www.kciade.online",
        "https://stake.com",
        "https://stake.ac",
        "https://stake.games",
        "https://stake.bet",
        "https://stake.pet",
        "https://stake.mba",
        "https://stake.jp",
        "https://stake.bz",
        "https://stake.ceo",
        "https://stake.krd",
        "https://staketr.com",
        "https://stake1001.com",
        "https://stake1002.com",
        "https://stake1003.com",
        "https://stake1017.com",
        "https://stake1021.com",
        "https://stake1022.com",
        "https://stake1039.com",
        "https://stake.us",
        "https://stake.br",
        "https://put-1.onrender.com"
    ]
    
    # Add Render host if available
    RENDER_HOST = os.environ.get('RENDER_EXTERNAL_URL', '')
    if RENDER_HOST:
        ALLOWED_ORIGINS.append(RENDER_HOST)
    
    # Development/localhost support - always allow localhost for testing
    ALLOWED_ORIGINS.extend([
        "http://localhost:3000",
        "http://localhost:5000",
        "http://127.0.0.1:5000",
        "http://127.0.0.1:3000"
    ])
    
    # Redis configuration for caching
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    
    # Redis connection pool settings
    REDIS_SOCKET_CONNECT_TIMEOUT = int(os.environ.get('REDIS_SOCKET_CONNECT_TIMEOUT', '5'))
    REDIS_SOCKET_TIMEOUT = int(os.environ.get('REDIS_SOCKET_TIMEOUT', '5'))
    
    # Pinned users - always kept in cache for fast WebSocket connections
    PINNED_USERS = ["bharat", "marc_henry"]



