import logging
from typing import Optional
import redis
from redis.exceptions import RedisError, ConnectionError as RedisConnectionError
from app.config import Config

# Configure logger
logger = logging.getLogger(__name__)

class UserAuthService:
    USER_KEY_PREFIX = "user:"
    RATE_LIMIT_PREFIX = "rate_limit:"
    RATE_LIMIT_TTL = 10
    
    def __init__(self, config: Config):
        self.config = config
        self.redis_client: Optional[redis.Redis] = None
        self._connect()
    
    def _connect(self) -> None:
        """Establish Redis connection with Render survival flags."""
        try:
            redis_url = self.config.REDIS_URL
            if not redis_url:
                logger.warning("REDIS_URL not configured")
                return
            
            connection_params = {
                'decode_responses': True,
                'socket_connect_timeout': self.config.REDIS_SOCKET_CONNECT_TIMEOUT,
                'socket_timeout': self.config.REDIS_SOCKET_TIMEOUT,
                'retry_on_timeout': True,
                'health_check_interval': 30,
                'socket_keepalive': True  # Keep connection alive on Render
            }
            
            if redis_url.startswith('rediss://'):
                import ssl
                connection_params['ssl_cert_reqs'] = ssl.CERT_NONE
                connection_params['ssl_check_hostname'] = False
            
            self.redis_client = redis.from_url(redis_url, **connection_params)
            self.redis_client.ping()
            logger.info(f"Successfully connected to Redis at {redis_url}")
        except (RedisConnectionError, Exception) as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.redis_client = None

    def get_redis_client(self) -> Optional[redis.Redis]:
        """
        Self-healing Redis client access.
        Attempts to reconnect if the client is missing or disconnected.
        """
        try:
            if self.redis_client is None:
                logger.info("Redis client is None, attempting to reconnect...")
                self._connect()
            
            if self.redis_client:
                # Quick ping to ensure connection is still valid
                self.redis_client.ping()
                return self.redis_client
        except RedisError as e:
            logger.warning(f"Redis transient error during health check: {e}")
            self.redis_client = None
            # Try one immediate reconnection attempt
            self._connect()
            return self.redis_client
        
        return None
    
    def _get_user_key(self, username: str) -> str:
        return f"{self.USER_KEY_PREFIX}{username.lower()}"
    
    def _get_rate_limit_key(self, username: str) -> str:
        return f"{self.RATE_LIMIT_PREFIX}{username.lower()}"
    
    def _is_rate_limited(self, username: str) -> bool:
        client = self.get_redis_client()
        if not client:
            return False
        try:
            rate_limit_key = self._get_rate_limit_key(username)
            is_limited = client.exists(rate_limit_key) > 0
            if is_limited:
                logger.debug(f"User {username} is currently rate limited in Redis")
            return is_limited
        except RedisError as e:
            logger.error(f"Redis error checking rate limit for {username}: {e}")
            return False
    
    def _set_rate_limit(self, username: str) -> None:
        client = self.get_redis_client()
        if not client:
            return
        try:
            rate_limit_key = self._get_rate_limit_key(username)
            client.setex(rate_limit_key, self.RATE_LIMIT_TTL, "1")
            logger.debug(f"Set rate limit for {username} in Redis for {self.RATE_LIMIT_TTL}s")
        except RedisError as e:
            logger.error(f"Redis error setting rate limit for {username}: {e}")
            pass
    
    def verify_username(self, username: str) -> Optional[dict]:
        logger.debug(f"Verifying username: {username}")
        client = self.get_redis_client()
        if not client:
            logger.warning("Redis client not available for verify_username")
            return None
        if not username:
            return None
        
        try:
            user_key = self._get_user_key(username)
            user_data = client.hgetall(user_key)
            
            if user_data and user_data.get('user_id'):
                logger.info(f"User {username} found in Redis: {user_data}")
                return {
                    'user_id': int(user_data['user_id']),
                    'username': user_data.get('username', username)
                }
            
            logger.info(f"User {username} NOT found in Redis")
            
            if self._is_rate_limited(username):
                logger.info(f"Lookup for {username} skipped due to rate limit")
                return None
            
            logger.info(f"Triggering background DB lookup for {username}")
            self._lookup_and_cache_user(username)
            self._set_rate_limit(username)
            return None
        except (RedisError, ValueError) as e:
            logger.error(f"Error in verify_username for {username}: {e}")
            return None
    
    def _lookup_and_cache_user(self, username: str) -> None:
        try:
            import eventlet
            if hasattr(eventlet, 'spawn'):
                logger.debug(f"Spawning eventlet for DB lookup: {username}")
                eventlet.spawn(self._db_lookup_user, username)
                return
        except (ImportError, AttributeError):
            pass
        
        logger.debug(f"Starting thread for DB lookup: {username}")
        import threading
        thread = threading.Thread(target=self._db_lookup_user, args=(username,), daemon=True)
        thread.start()
    
    def _db_lookup_user(self, username: str) -> None:
        logger.info(f"Starting database lookup for user: {username}")
        try:
            from sqlalchemy import select, func
            from app.database import SessionLocal
            from app.models import User
            
            with SessionLocal() as session:
                row = session.execute(
                    select(User).where(func.lower(User.username) == username.lower())
                ).scalar_one_or_none()
                
                if row:
                    logger.info(f"User {username} found in DB (ID: {row.id}), caching to Redis")
                    self.set_user(row.username, row.id)
                else:
                    logger.info(f"User {username} NOT found in database")
        except Exception as e:
            logger.error(f"Database error during lookup for {username}: {e}", exc_info=True)
            pass
    
    def set_user(self, username: str, user_id: int) -> bool:
        client = self.get_redis_client()
        if not client:
            logger.warning("Redis client not available for set_user")
            return False
        
        try:
            user_key = self._get_user_key(username)
            logger.info(f"Caching user {username} (ID: {user_id}) to Redis at {user_key}")
            success = bool(client.hset(
                user_key,
                mapping={
                    'user_id': str(user_id),
                    'username': username
                }
            ))
            if success:
                logger.debug(f"Successfully cached {username} to Redis")
            return success
        except RedisError as e:
            logger.error(f"Redis error in set_user for {username}: {e}")
            return False
    
    def delete_user(self, username: str) -> bool:
        client = self.get_redis_client()
        if not client:
            return False
        
        try:
            user_key = self._get_user_key(username)
            logger.info(f"Deleting user {username} from Redis")
            return client.delete(user_key) > 0
        except RedisError as e:
            logger.error(f"Redis error in delete_user for {username}: {e}")
            return False
    
    def remove_stale_users(self, valid_usernames: set) -> int:
        client = self.get_redis_client()
        if not client:
            return 0
        
        try:
            pattern = f"{self.USER_KEY_PREFIX}*"
            deleted_count = 0
            pipeline_batch_size = 100
            keys_to_delete = []
            
            cursor = 0
            while True:
                cursor, keys = client.scan(cursor, match=pattern, count=100)
                
                for key in keys:
                    username_from_key = key.replace(self.USER_KEY_PREFIX, "").lower()
                    if username_from_key not in valid_usernames:
                        keys_to_delete.append(key)
                
                if cursor == 0:
                    break
            
            if keys_to_delete:
                logger.info(f"Removing {len(keys_to_delete)} stale users from Redis")
                pipe = client.pipeline()
                for i in range(0, len(keys_to_delete), pipeline_batch_size):
                    batch = keys_to_delete[i:i + pipeline_batch_size]
                    for key in batch:
                        pipe.delete(key)
                    pipe.execute()
                    deleted_count += len(batch)
            
            return deleted_count
        except RedisError as e:
            logger.error(f"Redis error in remove_stale_users: {e}")
            return 0
    
    def sync_users(self, users: list) -> int:
        client = self.get_redis_client()
        if not client:
            return 0
        
        try:
            logger.info(f"Syncing {len(users)} users to Redis")
            count = 0
            pipe = client.pipeline()
            
            for user in users:
                user_key = self._get_user_key(user['username'])
                pipe.hset(
                    user_key,
                    mapping={
                        'user_id': str(user['user_id']),
                        'username': user['username']
                    }
                )
                count += 1
            
            pipe.execute()
            logger.info(f"Successfully synced {count} users to Redis")
            return count
        except RedisError as e:
            logger.error(f"Redis error in sync_users: {e}")
            return 0
    
    def lookup_user_sync(self, username: str, timeout: float = 0.2) -> Optional[dict]:
        """
        Synchronous DB lookup with timeout.
        If user is found, cache it in Redis and return.
        """
        logger.info(f"Starting synchronous DB lookup for {username} (timeout: {timeout}s)")
        try:
            from sqlalchemy import select, func
            from app.database import SessionLocal
            from app.models import User
            import threading
            
            result = [None]
            
            def query_db():
                try:
                    with SessionLocal() as session:
                        logger.debug(f"Executing DB query for {username}")
                        row = session.execute(
                            select(User).where(func.lower(User.username) == username.lower())
                        ).scalar_one_or_none()
                        
                        if row:
                            logger.info(f"Sync DB lookup: User {username} found (ID: {row.id})")
                            result[0] = {
                                'user_id': row.id,
                                'username': row.username
                            }
                            # Cache in Redis for next time
                            self.set_user(row.username, row.id)
                        else:
                            logger.info(f"Sync DB lookup: User {username} NOT found")
                except Exception as e:
                    logger.error(f"Sync DB lookup error for {username}: {e}")
                    pass
            
            thread = threading.Thread(target=query_db, daemon=True)
            thread.start()
            thread.join(timeout=timeout)
            
            if thread.is_alive():
                logger.warning(f"Sync DB lookup for {username} timed out after {timeout}s")
            
            return result[0]
        except Exception as e:
            logger.error(f"Error in lookup_user_sync for {username}: {e}")
            return None
    
    def is_available(self) -> bool:
        return self.get_redis_client() is not None


user_auth_service: Optional[UserAuthService] = None


def init_user_auth_service(config: Config) -> UserAuthService:
    global user_auth_service
    if user_auth_service is None:
        user_auth_service = UserAuthService(config)
    return user_auth_service


def get_user_auth_service() -> Optional[UserAuthService]:
    return user_auth_service
