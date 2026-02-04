"""
WebSocket connection and code broadcasting manager.
"""
import hashlib
import threading
import time
import logging
from datetime import datetime
from typing import Optional

# Configure logger
logger = logging.getLogger(__name__)

class WebSocketManager:
    """Manages WebSocket connections and code broadcasting."""
    
    def __init__(self, deduplication_window_seconds: int = 5):
        self.clients = {}  # {sid: {'namespace': str, 'username': str, 'connected_at': datetime}}
        self.code_history = []  # Store recent codes
        self.max_history = 100
        
        # Deduplication: track recently broadcast codes to prevent duplicates
        # Format: {code_hash: timestamp}
        self._recent_codes: dict[str, float] = {}
        self._deduplication_window = deduplication_window_seconds
        self._deduplication_lock = threading.Lock()
    
    def add_client(self, sid, namespace='default', user=None):
        """Add a client to the manager."""
        username = user.get('username') if isinstance(user, dict) else None
        user_id = user.get('user_id') if isinstance(user, dict) else None
        
        logger.info(f"WS Manager: Adding client SID: {sid}, Namespace: {namespace}, User: {username} (ID: {user_id})")
        
        self.clients[sid] = {
            'namespace': namespace,
            'username': username,
            'user_id': user_id,
            'connected_at': datetime.now()
        }
    
    def remove_client(self, sid):
        """Remove a client from the manager."""
        if sid in self.clients:
            client = self.clients[sid]
            logger.info(f"WS Manager: Removing client SID: {sid}, User: {client.get('username')}")
            del self.clients[sid]
        else:
            logger.debug(f"WS Manager: Attempted to remove non-existent client SID: {sid}")
    
    def get_client(self, sid) -> Optional[dict]:
        """Return client metadata if connected."""
        return self.clients.get(sid)
    
    def _generate_code_hash(self, code_value: str) -> str:
        """Generate a hash for the code value for deduplication."""
        return hashlib.sha256(code_value.encode('utf-8')).hexdigest()
    
    def _cleanup_old_codes(self, current_time: float):
        """
        Remove codes older than deduplication window.
        Efficiently removes expired entries to prevent memory growth.
        
        Args:
            current_time: Current timestamp to use for comparison
        """
        cutoff_time = current_time - self._deduplication_window
        
        with self._deduplication_lock:
            # Efficiently remove expired entries
            expired_keys = [
                code_hash for code_hash, timestamp in self._recent_codes.items()
                if timestamp < cutoff_time
            ]
            for key in expired_keys:
                del self._recent_codes[key]
    
    def is_code_duplicate(self, code_value: str) -> bool:
        """
        Check if a code was recently broadcast (within deduplication window).
        Automatically cleans up expired entries on every check to prevent memory growth.
        
        Args:
            code_value: The code string to check
            
        Returns:
            True if code is a duplicate (within window), False otherwise
        """
        if not code_value:
            return False
        
        code_hash = self._generate_code_hash(code_value)
        current_time = time.time()
        
        # Clean up expired entries on every check (prevents memory growth)
        self._cleanup_old_codes(current_time)
        
        with self._deduplication_lock:
            if code_hash in self._recent_codes:
                last_broadcast_time = self._recent_codes[code_hash]
                time_since_broadcast = current_time - last_broadcast_time
                
                if time_since_broadcast < self._deduplication_window:
                    logger.debug(f"WS Manager: Duplicate code detected (hash: {code_hash[:8]}...)")
                    return True
            
            # Mark code as broadcast (update timestamp)
            self._recent_codes[code_hash] = current_time
            return False
    
    def broadcast_code(self, code_data, socketio_instance=None):
        """
        Broadcast code to all connected clients (both Socket.IO and SSE).
        Includes deduplication check to prevent duplicate broadcasts within the window.
        
        Args:
            code_data: Dictionary containing code information
            socketio_instance: SocketIO instance to use for broadcasting
            
        Returns:
            bool: True if code was broadcast, False if it was a duplicate
        """
        # Extract code value for deduplication
        code_value = code_data.get('code', '')
        if not code_value:
            logger.warning("WS Manager: Attempted to broadcast empty code")
            return False
        
        # Check for duplicates (within deduplication window)
        if self.is_code_duplicate(code_value):
            return False
        
        # Add timestamp if not present
        if 'timestamp' not in code_data:
            code_data['timestamp'] = datetime.now().isoformat()
        
        # Store in history
        self.code_history.append(code_data)
        if len(self.code_history) > self.max_history:
            self.code_history.pop(0)
        
        logger.info(f"WS Manager: Broadcasting code to clients. History size: {len(self.code_history)}")
        
        # Broadcast to Socket.IO clients
        if socketio_instance:
            # Broadcast to /events namespace (code listeners)
            logger.debug("WS Manager: Emitting to /events namespace (room: code_listeners)")
            socketio_instance.emit('new_code', code_data, room='code_listeners', namespace='/events')
            
            # Also broadcast to default namespace
            logger.debug("WS Manager: Emitting to default namespace")
            socketio_instance.emit('new_code', code_data)
        
        # Broadcast to SSE clients
        from app.sse_manager import sse_manager
        logger.debug("WS Manager: Forwarding to sse_manager")
        sse_manager.broadcast_code(code_data)
        
        return True
    
    def get_client_count(self):
        """Get the number of connected clients."""
        return len(self.clients)
    
    def get_code_history(self, limit=10):
        """Get recent code history."""
        return self.code_history[-limit:]


# Global instance
websocket_manager = WebSocketManager()
