import hashlib
import logging
from datetime import datetime, timezone

import http_sfv
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import HTTPException, Request, status
from http_message_signatures import (
    HTTPMessageVerifier,
    HTTPSignatureKeyResolver,
    VerifyResult,
    algorithms,
)
from http_message_signatures.exceptions import InvalidSignature
from werkzeug.utils import safe_join

HASH_ALGORITHMS = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}


class MyHTTPSignatureKeyResolver(HTTPSignatureKeyResolver):
    def __init__(self, client_database: str):
        self.client_database = client_database

    def resolve_public_key(self, key_id: str):
        filename = safe_join(self.client_database, f"{key_id}.pem")
        try:
            with open(filename, "rb") as fp:
                return load_pem_public_key(fp.read())
        except FileNotFoundError:
            raise KeyError(key_id)


class ContentDigestException(ValueError):
    pass


class InvalidContentDigest(ContentDigestException):
    pass


class UnsupportedContentDigestAlgorithm(ContentDigestException):
    pass


class ContentDigestMissing(ContentDigestException):
    pass


class RequestVerifier:
    def __init__(self, client_database: str):
        self.algorithm = algorithms.ECDSA_P256_SHA256
        self.key_resolver = MyHTTPSignatureKeyResolver(client_database)
        self.logger = logging.getLogger(__name__).getChild(self.__class__.__name__)

    async def verify_content_digest(self, result: VerifyResult, request: Request):
        """Verify Content-Digest"""
        if content_digest := result.covered_components.get('"content-digest"'):
            content_digest_value = http_sfv.Dictionary()
            content_digest_value.parse(content_digest.encode())
            for alg, func in HASH_ALGORITHMS.items():
                if digest := content_digest_value.get(alg):
                    if digest.value == func(await request.body()).digest():
                        return
                    raise InvalidContentDigest
            raise UnsupportedContentDigestAlgorithm
        raise ContentDigestMissing

    async def verify(self, request: Request) -> dict:
        """Verify request and return signer"""
        verifier = HTTPMessageVerifier(
            signature_algorithm=self.algorithm,
            key_resolver=self.key_resolver,
        )
        try:
            results = verifier.verify(request)
        except KeyError as exc:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "Unknown HTTP signature key"
            )
        except InvalidSignature:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid HTTP signature")
        except Exception as exc:
            self.logger.warning("Unable to verify HTTP signature", exc_info=exc)
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "Unable to verify HTTP signature"
            )

        for result in results:
            try:
                await self.verify_content_digest(result, request)
                self.logger.debug("Content-Digest verified")
                return result.parameters
            except InvalidContentDigest:
                raise HTTPException(
                    status.HTTP_401_UNAUTHORIZED, "Content-Digest verification failed"
                )
            except UnsupportedContentDigestAlgorithm:
                self.logger.debug("Unsupported Content-Digest algorithm")
            except ContentDigestMissing:
                self.logger.debug("Content-Digest header missing")

        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Unable to verify Content-Digest"
        )


def rfc_3339_datetime_now() -> str:
    """Return current time(UTC) as ISO 8601 timestamp"""
    return str(datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
