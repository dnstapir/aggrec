import os
import uuid

import cryptography.hazmat.primitives.asymmetric.ec as ec
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
import httpx2
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from http_message_signatures import HTTPMessageSigner, HTTPSignatureAlgorithm, HTTPSignatureKeyResolver, algorithms
from starlette.datastructures import Headers
from starlette.exceptions import HTTPException
from starlette.requests import Request

from aggrec.helpers import RequestVerifier


def build_starlette_request(
    method: str = "GET",
    server: str = "www.example.com",
    path: str = "/",
    headers: dict[str, str] | None = None,
    content: bytes | None = None,
) -> Request:
    """Build a Starlette Request object for testing purposes."""

    request = Request(
        {
            "type": "http",
            "path": path,
            "headers": Headers(headers or {}).raw,
            "http_version": "1.1",
            "method": method,
            "scheme": "https",
            "client": ("127.0.0.1", 8080),
            "server": (server, 443),
        }
    )

    if content:
        # Directly set the request body for testing purposes
        request._body = content

    return request


class UnsupportedHTTPSignatureAlgorithm(HTTPSignatureAlgorithm):
    algorithm_id = "xyzzy"

    def __init__(self, public_key=None, private_key=None, password=None):
        pass

    def sign(self, message: bytes):
        return os.urandom(64)  # Return 64 random bytes as a fake signature


class TestHTTPSignatureKeyResolver(HTTPSignatureKeyResolver):
    def __init__(self, key_id: str, algorithm: HTTPSignatureAlgorithm):
        self.algorithm = algorithm
        self.key_id = key_id
        match algorithm:
            case algorithms.ECDSA_P256_SHA256:
                self.private_key = ec.generate_private_key(ec.SECP256R1())
            case algorithms.ED25519:
                self.private_key = ed25519.Ed25519PrivateKey.generate()
            case algorithms.RSA_V1_5_SHA256 | algorithms.RSA_PSS_SHA512:
                self.private_key = rsa.generate_private_key(key_size=2048, public_exponent=65537)
            case _:
                raise ValueError("Unsupported algorithm")
        self.public_key = self.private_key.public_key()

    def resolve_public_key(self, key_id: str):
        if key_id == self.key_id:
            return self.public_key
        raise KeyError(key_id)

    def resolve_private_key(self, key_id: str):
        if key_id == self.key_id:
            return self.private_key
        raise KeyError(key_id)


async def _test_http_signatures(
    algorithm: HTTPSignatureAlgorithm,
    signature_algorithm: HTTPSignatureAlgorithm | None = None,
    remove_signature: bool = False,
):
    key_id = "test"
    covered_component_ids = ["content-type", "content-digest", "content-length"]

    client = httpx2.Client(verify=False)

    req = client.build_request("POST", "https://localhost/test", content=os.urandom(1024))

    req.headers["X-Request-ID"] = str(uuid.uuid4())
    req.headers["Content-Type"] = "application/binary"

    key_resolver = TestHTTPSignatureKeyResolver(key_id=key_id, algorithm=algorithm)
    signer = HTTPMessageSigner(signature_algorithm=signature_algorithm or algorithm, key_resolver=key_resolver)
    verifier = RequestVerifier(
        key_resolver=key_resolver,
        require_components=["content-type", "content-digest", "content-length"],
    )
    verifier2 = RequestVerifier(
        key_resolver=key_resolver,
        require_components=["user-agent"],
    )

    signer.sign(
        req,
        key_id=key_id,
        label="client",
        covered_component_ids=covered_component_ids,
        include_alg=True,
        body=req.content,
    )

    if remove_signature:
        req.headers.pop("signature", None)
        req.headers.pop("signature-input", None)

    request = build_starlette_request(
        method="POST",
        server="localhost",
        path="/test",
        headers=req.headers,
        content=req.content,
    )

    result, _ = await verifier.verify(request)

    with pytest.raises(HTTPException) as exc_info:
        await verifier2.verify(request)
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_http_signatures_rsa_pkcs1_sha256():
    return await _test_http_signatures(algorithms.RSA_V1_5_SHA256)


@pytest.mark.asyncio
async def test_http_signatures_rsa_pss_sha512():
    return await _test_http_signatures(algorithms.RSA_PSS_SHA512)


@pytest.mark.asyncio
async def test_http_signatures_ecdsa_p256_sha256():
    return await _test_http_signatures(algorithms.ECDSA_P256_SHA256)


@pytest.mark.asyncio
async def test_http_signatures_ed25519():
    return await _test_http_signatures(algorithms.ED25519)


@pytest.mark.asyncio
async def test_http_unknown_signature():
    with pytest.raises(HTTPException) as exc_info:
        await _test_http_signatures(algorithms.ED25519, UnsupportedHTTPSignatureAlgorithm)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Unsupported signature algorithm"


@pytest.mark.asyncio
async def test_missing_http_signatures():
    with pytest.raises(HTTPException) as exc_info:
        await _test_http_signatures(algorithms.ED25519, remove_signature=True)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Signature-Input header missing"
