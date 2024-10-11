import logging
import time
from abc import abstractmethod

import redis
from expiringdict import ExpiringDict

logger = logging.getLogger(__name__)


DEFAULT_MEMORY_CACHE_SIZE = 1000
DEFAULT_MEMORY_CACHE_TTL = 60


class KeyCache:
    @abstractmethod
    def get(self, key: str) -> bytes | None:
        return None

    @abstractmethod
    def set(self, key: str, value: bytes, ttl: int | None = None) -> None:
        pass


class DummyKeyCache(KeyCache):
    def get(self, key: str) -> bytes | None:
        return None

    def set(self, key: str, value: bytes, ttl: int | None = None) -> None:
        pass


class MemoryKeyCache(KeyCache):
    def __init__(self, size: int = DEFAULT_MEMORY_CACHE_SIZE, ttl: int = DEFAULT_MEMORY_CACHE_TTL):
        self.cache = ExpiringDict(max_len=size, max_age_seconds=ttl)

    def get(self, key: str) -> bytes | None:
        res = self.cache.get(key)
        logger.debug("Cache GET %s (%s)", key, "hit" if res else "miss")
        return res

    def set(self, key: str, value: bytes, ttl: int | None = None) -> None:
        logger.debug("Cache SET %s", key)
        self.cache[key] = value


class RedisKeyCache(KeyCache):
    def __init__(self, redis_client: redis.Redis, default_ttl: int):
        self.redis_client = redis_client
        self.default_ttl = default_ttl

    def get(self, key: str) -> bytes | None:
        res = self.redis_client.get(name=key)
        logger.debug("Cache GET %s (%s)", key, "hit" if res else "miss")
        return res

    def set(self, key: str, value: bytes, ttl: int | None = None) -> None:
        ttl = ttl if ttl is not None else self.default_ttl
        expires_at = int(time.time()) + ttl
        logger.debug("Cache SET %s with TTL %d EXAT %d", key, ttl, expires_at)
        self.redis_client.set(name=key, value=value, exat=expires_at)
