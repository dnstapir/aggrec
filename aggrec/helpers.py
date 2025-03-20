import hashlib
import logging
from datetime import datetime, timedelta

import aniso8601
import http_sf
from fastapi import HTTPException, Request, status
from http_message_signatures import (
    HTTPMessageVerifier,
    HTTPSignatureAlgorithm,
    HTTPSignatureKeyResolver,
    VerifyResult,
    algorithms,
)
from http_message_signatures.algorithms import signature_algorithms as supported_signature_algorithms
from http_message_signatures.exceptions import InvalidSignature

from dnstapir.key_resolver import KeyResolver, PublicKey

DEFAULT_SIGNATURE_ALGORITHM = algorithms.ECDSA_P256_SHA256
HASH_ALGORITHMS = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}


class ContentDigestException(ValueError):
    pass


class InvalidContentDigest(ContentDigestException):
    pass


class UnsupportedContentDigestAlgorithm(ContentDigestException):
    pass


class ContentDigestMissing(ContentDigestException):
    pass


class CustomHTTPSignatureKeyResolver(HTTPSignatureKeyResolver):
    def __init__(self, key_resolver: KeyResolver):
        self.key_resolver = key_resolver

    def resolve_public_key(self, key_id: str) -> PublicKey:
        return self.key_resolver.resolve_public_key(key_id=key_id)


class RequestVerifier:
    def __init__(
        self,
        key_resolver: KeyResolver,
        algorithm: HTTPSignatureAlgorithm | None = None,
    ):
        self.algorithm = algorithm or DEFAULT_SIGNATURE_ALGORITHM
        self.http_key_resolver = CustomHTTPSignatureKeyResolver(key_resolver)
        self.logger = logging.getLogger(__name__).getChild(self.__class__.__name__)

    async def verify_content_digest(self, result: VerifyResult, request: Request):
        """Verify Content-Digest"""
        if content_digest := result.covered_components.get('"content-digest"'):
            content_digest_value = http_sf.parse(content_digest.encode(), tltype="dictionary")
            for alg, func in HASH_ALGORITHMS.items():
                if digest := content_digest_value.get(alg):
                    if digest[0] == func(await request.body()).digest():
                        return
                    raise InvalidContentDigest
            raise UnsupportedContentDigestAlgorithm
        raise ContentDigestMissing

    @staticmethod
    def get_algorithm(headers: dict) -> str | None:
        parse_signature_input = http_sf.parse(headers["signature-input"].encode(), tltype="dictionary")
        for _label, values in parse_signature_input.items():
            for item in values:
                if isinstance(item, dict) and (alg := item.get("alg")) and isinstance(alg, str):
                    return str(alg)
        return

    async def verify(self, request: Request) -> VerifyResult:
        """Verify request and return signer"""

        logger_extra = {
            "http_request_method": request.method,
            "http_request_url": request.url,
            "http_request_headers": request.headers,
        }

        self.logger.debug("Verify HTTP request", extra=logger_extra)

        alg = self.get_algorithm(request.headers)
        signature_algorithm = supported_signature_algorithms[alg]
        verifier = HTTPMessageVerifier(
            signature_algorithm=signature_algorithm,
            key_resolver=self.http_key_resolver,
        )

        try:
            results = verifier.verify(request)
        except KeyError as exc:
            msg = "Unknown HTTP signature key"
            self.logger.warning(msg, extra=logger_extra, exc_info=exc)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, msg) from exc
        except InvalidSignature as exc:
            msg = "Invalid HTTP signature"
            self.logger.warning(msg, extra=logger_extra, exc_info=exc)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, msg) from exc
        except Exception as exc:
            msg = "Unable to verify HTTP signature"
            self.logger.warning(msg, extra=logger_extra, exc_info=exc)
            raise HTTPException(status.HTTP_400_BAD_REQUEST, msg) from exc

        for result in results:
            try:
                await self.verify_content_digest(result, request)
                self.logger.debug("Content-Digest verified")
                return result
            except InvalidContentDigest as exc:
                msg = "Content-Digest verification failed"
                self.logger.warning(msg, extra=logger_extra, exc_info=exc)
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, msg) from exc
            except UnsupportedContentDigestAlgorithm:
                self.logger.debug("Unsupported Content-Digest algorithm")
            except ContentDigestMissing:
                self.logger.debug("Content-Digest header missing")

        msg = "Unable to verify Content-Digest"
        self.logger.warning(msg, extra=logger_extra)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, msg)


def rfc_3339_datetime_now() -> str:
    """Return current time(UTC) as ISO 8601 timestamp"""
    return str(datetime.now(tz=datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))


def parse_iso8601_interval(interval: str) -> tuple[datetime, timedelta]:
    """Parse ISO8601 interval and return resulting datetime and timedelta"""
    t1, t2 = aniso8601.parse_interval(interval)
    if not isinstance(t1, datetime) or not isinstance(t2, datetime):
        raise ValueError("Invalid interval format")
    if t1.tzinfo is None:
        raise ValueError("Start time must include timezone")
    if t2.tzinfo is None:
        raise ValueError("End time must include timezone")
    t1 = t1.astimezone(datetime.UTC)
    t2 = t2.astimezone(datetime.UTC)
    duration = timedelta(seconds=(t2 - t1).total_seconds())
    if duration.total_seconds() < 0:
        raise ValueError("Duration cannot be negative")
    return t1, duration
