"""
In-memory cache for pinned users only.
All other users are stored in Redis.
"""
from __future__ import annotations

import threading
from typing import Dict, Optional

from sqlalchemy import func, select

from app.config import Config
from app.database import SessionLocal
from app.models import User


class UserService:
    """
    In-memory cache for pinned users only.
    All other users are stored in Redis.
    """

    def __init__(self):
        self._cache: Dict[str, dict] = {}
        # Use regular Lock instead of RLock for eventlet compatibility
        self._lock = threading.Lock()
        self._pinned_users = {u.lower() for u in Config.PINNED_USERS}

    def start(self) -> None:
        """
        Preload pinned users into local cache on startup.
        """
        try:
            self._preload_pinned_users()
        except Exception as e:
            import logging
            logging.warning(f"UserService: Failed to preload pinned users: {e}")

    def stop(self) -> None:
        """
        Cleanup (no-op for pinned-only cache).
        """
        pass

    # Internal helpers -------------------------------------------------

    def _preload_pinned_users(self) -> None:
        """Preload pinned users into local cache on startup."""
        try:
            with SessionLocal() as session:
                for username in self._pinned_users:
                    try:
                        row = session.execute(
                            select(User).where(func.lower(User.username) == username)
                        ).scalar_one_or_none()
                        
                        if row:
                            with self._lock:
                                self._cache[username] = {
                                    "user_id": row.id,
                                    "username": row.username,
                                    "expires_at": float('inf'),  # Never expire
                                }
                    except Exception:
                        pass
        except Exception:
            pass

    def _normalize(self, username: Optional[str]) -> Optional[str]:
        if username is None:
            return None
        username = str(username).strip()
        if not username or len(username) > 64:
            return None
        return username.lower()

    def _get_from_cache(self, normalized: str) -> Optional[dict]:
        """
        Get user from local cache (only pinned users are cached here).
        Returns None if not a pinned user or not found.
        """
        if normalized not in self._pinned_users:
            return None
        
        with self._lock:
            return self._cache.get(normalized)


user_service = UserService()

