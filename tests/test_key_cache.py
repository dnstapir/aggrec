import fakeredis
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from aggrec.key_cache import CombinedKeyCache, KeyCache, MemoryKeyCache, RedisKeyCache


def _test_key_cache(key_cache: KeyCache):
    key_id = "xyzzy"
    public_key = ed25519.Ed25519PrivateKey.generate().public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    res = key_cache.get(key_id)
    assert res is None

    key_cache.set(key_id, public_key_pem)

    res = key_cache.get(key_id)
    assert res == public_key_pem


def test_redis_cache():
    redis_client = fakeredis.FakeRedis()
    key_cache = RedisKeyCache(redis_client=redis_client, ttl=60)
    _test_key_cache(key_cache=key_cache)


def test_memory_cache():
    key_cache = MemoryKeyCache(size=100, ttl=60)
    _test_key_cache(key_cache=key_cache)


def test_memory_stack():
    redis_client = fakeredis.FakeRedis()
    memory_key_cache = MemoryKeyCache(size=100, ttl=60)
    redis_key_cache = RedisKeyCache(redis_client=redis_client, ttl=60)

    key_cache = CombinedKeyCache([memory_key_cache, redis_key_cache])
    _test_key_cache(key_cache=key_cache)
