from typing import Optional
import redis
from redis.exceptions import RedisError, ConnectionError as RedisConnectionError
from app.config import Config


class CacheService:
    CACHE_KEY_PREFIX = "exchange_rate:"
    CACHE_TTL_SECONDS = 24 * 60 * 60
    
    def __init__(self, config: Config):
        self.config = config
        self.redis_client: Optional[redis.Redis] = None
        self._connect()
    
    def _connect(self) -> None:
        try:
            redis_url = self.config.REDIS_URL
            if not redis_url:
                return
            
            connection_params = {
                'decode_responses': True,
                'socket_connect_timeout': self.config.REDIS_SOCKET_CONNECT_TIMEOUT,
                'socket_timeout': self.config.REDIS_SOCKET_TIMEOUT,
                'retry_on_timeout': True,
                'health_check_interval': 30
            }
            
            if redis_url.startswith('rediss://'):
                import ssl
                connection_params['ssl_cert_reqs'] = ssl.CERT_NONE
                connection_params['ssl_check_hostname'] = False
            
            self.redis_client = redis.from_url(redis_url, **connection_params)
            self.redis_client.ping()
        except (RedisConnectionError, Exception):
            self.redis_client = None
    
    def _get_cache_key(self, currency: str) -> str:
        return f"{self.CACHE_KEY_PREFIX}{currency.upper()}"
    
    def get_exchange_rate(self, currency: str) -> Optional[float]:
        if not self.redis_client:
            return None
        
        try:
            cache_key = self._get_cache_key(currency)
            cached_value = self.redis_client.get(cache_key)
            return float(cached_value) if cached_value else None
        except (RedisError, ValueError):
            return None
    
    def set_exchange_rate(self, currency: str, rate: float) -> bool:
        if not self.redis_client:
            return False
        
        try:
            cache_key = self._get_cache_key(currency)
            result = self.redis_client.setex(
                cache_key,
                self.CACHE_TTL_SECONDS,
                str(rate)
            )
            return bool(result)
        except RedisError as e:
            return False
    
    def invalidate_exchange_rate(self, currency: str) -> bool:
        if not self.redis_client:
            return False
        
        try:
            cache_key = self._get_cache_key(currency)
            return self.redis_client.delete(cache_key) > 0
        except RedisError:
            return False
    
    def invalidate_all_rates(self) -> bool:
        if not self.redis_client:
            return False
        
        try:
            pattern = f"{self.CACHE_KEY_PREFIX}*"
            keys = self.redis_client.keys(pattern)
            if keys:
                return self.redis_client.delete(*keys) > 0
            return True
        except RedisError:
            return False
    
    def preload_all_rates(self, exchange_rates: list) -> int:
        """Preload all exchange rates into Redis cache."""
        if not self.redis_client:
            import logging
            logging.warning("CacheService.preload_all_rates: Redis client not available")
            return 0
        
        try:
            count = 0
            pipe = self.redis_client.pipeline()
            
            for rate_data in exchange_rates:
                currency = rate_data.get('currency', '').strip().upper() if rate_data.get('currency') else None
                rate = rate_data.get('rate')
                
                if currency and rate and rate > 0:
                    cache_key = self._get_cache_key(currency)
                    pipe.setex(cache_key, self.CACHE_TTL_SECONDS, str(rate))
                    count += 1
            
            if count > 0:
                results = pipe.execute()
                import logging
                logging.info(f"CacheService.preload_all_rates: Executed pipeline with {count} rates, {len(results)} results")
                return count
            else:
                import logging
                logging.warning("CacheService.preload_all_rates: No valid rates to preload")
                return 0
        except RedisError as e:
            import logging
            logging.error(f"CacheService.preload_all_rates: Redis error: {e}", exc_info=True)
            return 0
        except Exception as e:
            import logging
            logging.error(f"CacheService.preload_all_rates: Unexpected error: {e}", exc_info=True)
            return 0
    
    def is_available(self) -> bool:
        if not self.redis_client:
            return False
        try:
            self.redis_client.ping()
            return True
        except RedisError:
            return False


cache_service: Optional[CacheService] = None


def init_cache_service(config: Config) -> CacheService:
    global cache_service
    if cache_service is None:
        cache_service = CacheService(config)
    return cache_service


def get_cache_service() -> Optional[CacheService]:
    return cache_service
