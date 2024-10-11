import fakeredis
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from aggrec.key_cache import MemoryKeyCache, RedisKeyCache


def test_redis_cache():
    key_id = "xyzzy"
    public_key = ed25519.Ed25519PrivateKey.generate().public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    redis_client = fakeredis.FakeRedis()
    key_cache = RedisKeyCache(redis_client=redis_client, default_ttl=60)

    res = key_cache.get(key_id)
    assert res is None

    key_cache.set(key_id, public_key_pem)

    res = key_cache.get(key_id)
    assert res == public_key_pem


def test_memory_cache():
    key_id = "xyzzy"
    public_key = ed25519.Ed25519PrivateKey.generate().public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    key_cache = MemoryKeyCache()

    res = key_cache.get(key_id)
    assert res is None

    key_cache.set(key_id, public_key_pem)

    res = key_cache.get(key_id)
    assert res == public_key_pem
