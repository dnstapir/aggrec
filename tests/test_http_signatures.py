import hashlib
import os
import uuid

import cryptography.hazmat.primitives.asymmetric.ec as ec
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
import http_sf
import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import ed25519
from http_message_signatures import HTTPMessageSigner, HTTPSignatureAlgorithm, HTTPSignatureKeyResolver, algorithms
from starlette.datastructures import Headers
from starlette.requests import Request

from aggrec.helpers import RequestVerifier


def build_starlette_request(
    method: str = "GET",
    server: str = "www.example.com",
    path: str = "/",
    headers: dict = None,
    body: str = None,
) -> Request:
    if headers is None:
        headers = {}
    request = Request(
        {
            "type": "http",
            "path": path,
            "headers": Headers(headers).raw,
            "http_version": "1.1",
            "method": method,
            "scheme": "https",
            "client": ("127.0.0.1", 8080),
            "server": (server, 443),
        }
    )
    if body:

        async def request_body():
            return body

        request.body = request_body
    return request


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


async def _test_http_signatures(algorithm: HTTPSignatureAlgorithm):
    key_id = "test"
    covered_component_ids = ["content-type", "content-digest", "content-length"]

    req = requests.Request("POST", "https://localhost/test", data=os.urandom(1024))

    req = req.prepare()
    req.headers["X-Request-ID"] = str(uuid.uuid4())
    req.headers["Content-Type"] = "application/binary"
    req.headers["Content-Digest"] = http_sf.ser({"sha-256": hashlib.sha256(req.body).digest()})

    key_resolver = TestHTTPSignatureKeyResolver(key_id=key_id, algorithm=algorithm)
    signer = HTTPMessageSigner(signature_algorithm=algorithm, key_resolver=key_resolver)
    verifier = RequestVerifier(algorithm=algorithm, key_resolver=key_resolver)

    signer.sign(
        req,
        key_id=key_id,
        label="client",
        covered_component_ids=covered_component_ids,
        include_alg=True,
    )
    print(req.headers)

    request = build_starlette_request(
        method="POST",
        server="localhost",
        path="/test",
        headers=req.headers,
        body=req.body,
    )

    result = await verifier.verify(request)
    print(result)


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
