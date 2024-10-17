import logging
import time
from abc import abstractmethod

import redis
from expiringdict import ExpiringDict
from opentelemetry import trace

tracer = trace.get_tracer("aggrec.tracer")


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
        self.logger.info("Configured memory key cache size=%d ttl=%d", size, ttl)

    def get(self, key: str) -> bytes | None:
        with tracer.start_as_current_span("memory_key_cache_get"):
            res = self.cache.get(key)
        self.logger.debug("Cache GET %s (%s)", key, "hit" if res else "miss")
        return res

    def set(self, key: str, value: bytes) -> None:
        self.logger.debug("Cache SET %s", key)
        with tracer.start_as_current_span("memory_key_cache_set"):
            self.cache[key] = value


class RedisKeyCache(KeyCache):
    def __init__(self, redis_client: redis.Redis, ttl: int):
        super().__init__()
        self.redis_client = redis_client
        self.ttl = ttl
        self.logger.info("Configured Redis key cache ttl=%d", ttl)

    def get(self, key: str) -> bytes | None:
        with tracer.start_as_current_span("redis_key_cache_get"):
            res = self.redis_client.get(name=key)
        self.logger.debug("Cache GET %s (%s)", key, "hit" if res else "miss")
        return res

    def set(self, key: str, value: bytes) -> None:
        self.logger.debug("Cache SET %s", key)
        expires_at = int(time.time()) + self.ttl
        with tracer.start_as_current_span("redis_key_cache_set"):
            self.redis_client.set(name=key, value=value, exat=expires_at)


class CombinedKeyCache(KeyCache):
    def __init__(self, caches: list[KeyCache]):
        self.caches = caches

    def get(self, key: str) -> bytes | None:
        for cache in self.caches:
            if res := cache.get(key):
                return res
        return None

    def set(self, key: str, value: bytes) -> None:
        for cache in self.caches:
            cache.set(key, value)
