import logging
import time
from abc import abstractmethod

import redis
from expiringdict import ExpiringDict

logger = logging.getLogger(__name__)


class KeyCache:
    @abstractmethod
    def get(self, key: str) -> bytes | None:
        return None

    @abstractmethod
    def set(self, key: str, value: bytes) -> None:
        pass


class DummyKeyCache(KeyCache):
    def get(self, key: str) -> bytes | None:
        return None

    def set(self, key: str, value: bytes) -> None:
        pass


class MemoryKeyCache(KeyCache):
    def __init__(self, size: int, ttl: int):
        self.cache = ExpiringDict(max_len=size, max_age_seconds=ttl)
        logger.info("Using memory cache size=%d ttl=%d", size, ttl)

    def get(self, key: str) -> bytes | None:
        res = self.cache.get(key)
        logger.debug("Cache GET %s (%s)", key, "hit" if res else "miss")
        return res

    def set(self, key: str, value: bytes) -> None:
        logger.debug("Cache SET %s", key)
        self.cache[key] = value


class RedisKeyCache(KeyCache):
    def __init__(self, redis_client: redis.Redis, ttl: int):
        self.redis_client = redis_client
        self.ttl = ttl
        logger.info("Using Redis cache ttl=%d", ttl)

    def get(self, key: str) -> bytes | None:
        res = self.redis_client.get(name=key)
        logger.debug("Cache GET %s (%s)", key, "hit" if res else "miss")
        return res

    def set(self, key: str, value: bytes) -> None:
        logger.debug("Cache SET %s", key)
        expires_at = int(time.time()) + self.ttl
        self.redis_client.set(name=key, value=value, exat=expires_at)
