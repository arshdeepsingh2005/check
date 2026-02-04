"""
Database utilities and SQLAlchemy session management.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import NullPool, QueuePool
from dotenv import load_dotenv
load_dotenv()


DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    import logging
    import sys
    # Configure logging if not already configured
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=logging.ERROR,
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            stream=sys.stderr
        )
    logger = logging.getLogger(__name__)
    error_msg = (
        "=" * 60 + "\n"
        "FATAL ERROR: DATABASE_URL environment variable is required!\n"
        "=" * 60 + "\n"
        "To fix this:\n"
        "1. Go to Render Dashboard → Your Service → Environment\n"
        "2. Add environment variable: DATABASE_URL\n"
        "3. Set value to your PostgreSQL connection string\n"
        "   Example: postgresql://user:pass@host:5432/dbname?sslmode=require\n"
        "4. Save and redeploy\n"
        "=" * 60
    )
    logger.error(error_msg)
    print(error_msg, file=sys.stderr)
    raise RuntimeError(
        "DATABASE_URL environment variable is required. "
        "Set it in Render dashboard → Environment → DATABASE_URL"
    )

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    # Required for SQLite when used across multiple threads (SocketIO workers).
    connect_args["check_same_thread"] = False

# Add connection timeout for faster failure if DB is unreachable
connect_args_with_timeout = connect_args.copy()
if DATABASE_URL.startswith("postgresql"):
    # PostgreSQL connection timeout (in seconds)
    connect_args_with_timeout.setdefault("connect_timeout", 10)

# Detect if running in eventlet environment (production with Gunicorn eventlet workers)
# Eventlet's green threads don't work well with SQLAlchemy's QueuePool locks
is_eventlet = (
    os.environ.get('GUNICORN_CMD_ARGS') is not None or
    os.environ.get('SERVER_SOFTWARE', '').startswith('gunicorn') or
    os.environ.get('PORT') is not None  # Render sets this
)

# Use NullPool for eventlet to avoid lock issues with green threads
# NullPool creates a new connection for each request (no pooling)
# This is safe for eventlet since each green thread gets its own connection
if is_eventlet and DATABASE_URL.startswith("postgresql"):
    # NullPool doesn't support pool_timeout or pool_recycle
    engine = create_engine(
        DATABASE_URL,
        poolclass=NullPool,
        pool_pre_ping=True,
        future=True,
        echo=False,
        connect_args=connect_args_with_timeout,
    )
else:
    # Use QueuePool for non-eventlet environments (local development, threading mode)
    engine = create_engine(
        DATABASE_URL,
        poolclass=QueuePool,
        pool_pre_ping=True,
        pool_recycle=3600,  # Recycle connections after 1 hour
        pool_timeout=10,    # Timeout when getting connection from pool
        future=True,
        echo=False,
        connect_args=connect_args_with_timeout,
    )

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)

Base = declarative_base()


def init_db() -> None:
    """
    Import models and create tables. Should be invoked once during startup.
    """
    import logging
    try:
        from app import models  # noqa: F401  (side-effect import)
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        logging.error(f"Error initializing database: {e}", exc_info=True)
        raise


@contextmanager
def db_session() -> Generator:
    """
    Context manager that yields a SQLAlchemy session and guarantees cleanup.
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

