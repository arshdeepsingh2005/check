import threading
import time
from typing import Optional
from sqlalchemy import select, func
from app.database import SessionLocal
from app.models import User
from app.services.user_auth_service import get_user_auth_service


class UserSyncWorker:
    def __init__(self, sync_interval: int = 300):
        self.sync_interval = sync_interval
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
    
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        
        self._stop_event.clear()
        self.sync_all_users()
        
        self._thread = threading.Thread(
            target=self._sync_loop,
            name="user-sync-worker",
            daemon=True
        )
        self._thread.start()
    
    def stop(self) -> None:
        if not self._thread:
            return
        self._stop_event.set()
        self._thread.join(timeout=5)
        self._thread = None
    
    def sync_all_users(self) -> int:
        auth_service = get_user_auth_service()
        if not auth_service or not auth_service.is_available():
            return 0
        
        try:
            with SessionLocal() as session:
                rows = session.execute(
                    select(User.id, func.lower(User.username).label('username_lower'), User.username)
                ).all()
            
            users = [{
                'user_id': row.id,
                'username': row.username.strip()
            } for row in rows if row.username]
            
            db_usernames = {user['username'].lower() for user in users}
            
            deleted_count = auth_service.remove_stale_users(db_usernames)
            synced_count = auth_service.sync_users(users)
            
            return synced_count
        except Exception:
            return 0
    
    def _sync_loop(self) -> None:
        while not self._stop_event.wait(self.sync_interval):
            self.sync_all_users()


user_sync_worker = UserSyncWorker()

