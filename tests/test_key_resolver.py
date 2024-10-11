from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pytest_httpx import HTTPXMock

from aggrec.key_cache import MemoryKeyCache
from aggrec.key_resolver import UrlKeyResolver


def test_url_key_resolver(httpx_mock: HTTPXMock):
    key_id = "xyzzy"
    public_key = ed25519.Ed25519PrivateKey.generate().public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    httpx_mock.add_response(url=f"https://keys/{key_id}.pem", content=public_key_pem)

    resolver = UrlKeyResolver(client_database_base_url="https://keys", key_cache=MemoryKeyCache())

    res = resolver.resolve_public_key(key_id)
    assert res == public_key
