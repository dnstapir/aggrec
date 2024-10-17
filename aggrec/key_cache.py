import logging
import time
from abc import abstractmethod

import redis
from expiringdict import ExpiringDict


class KeyCache:
    def __init__(self):
        self.logger = logging.getLogger(__name__).getChild(self.__class__.__name__)

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
        super().__init__()
        self.cache = ExpiringDict(max_len=size, max_age_seconds=ttl)
        self.logger.info("Using memory cache size=%d ttl=%d", size, ttl)

    def get(self, key: str) -> bytes | None:
        res = self.cache.get(key)
        self.logger.debug("Cache GET %s (%s)", key, "hit" if res else "miss")
        return res

    def set(self, key: str, value: bytes) -> None:
        self.logger.debug("Cache SET %s", key)
        self.cache[key] = value


class RedisKeyCache(KeyCache):
    def __init__(self, redis_client: redis.Redis, ttl: int):
        super().__init__()
        self.redis_client = redis_client
        self.ttl = ttl
        self.logger.info("Using Redis cache ttl=%d", ttl)

    def get(self, key: str) -> bytes | None:
        res = self.redis_client.get(name=key)
        self.logger.debug("Cache GET %s (%s)", key, "hit" if res else "miss")
        return res

    def set(self, key: str, value: bytes) -> None:
        self.logger.debug("Cache SET %s", key)
        expires_at = int(time.time()) + self.ttl
        self.redis_client.set(name=key, value=value, exat=expires_at)


class MemoryRedisKeyCache(KeyCache):
    def __init__(self, size: int, ttl: int, redis_client: redis.Redis):
        super().__init__()
        self.memory_cache = MemoryKeyCache(size, ttl)
        self.redis_cache = RedisKeyCache(redis_client, ttl)
        self.logger.info("Using memory+redis cache size=%d ttl=%d", size, ttl)

    def get(self, key: str) -> bytes | None:
        return self.memory_cache.get(key) or self.redis_cache.get(key)

    def set(self, key: str, value: bytes) -> None:
        self.memory_cache.set(key, value)
        self.redis_cache.set(key, value)
