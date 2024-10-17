import hashlib
import logging
from datetime import datetime, timezone

import http_sf
import pendulum
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
from pydantic import AnyHttpUrl, DirectoryPath

from .key_cache import KeyCache
from .key_resolver import FileKeyResolver, UrlKeyResolver

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


class RequestVerifier:
    def __init__(
        self,
        algorithm: HTTPSignatureAlgorithm | None = None,
        key_resolver: HTTPSignatureKeyResolver | None = None,
        client_database: AnyHttpUrl | DirectoryPath | None = None,
        key_cache: KeyCache | None = None,
    ):
        self.algorithm = algorithm or DEFAULT_SIGNATURE_ALGORITHM
        if key_resolver:
            self.key_resolver = key_resolver
        elif client_database and (
            str(client_database).startswith("http://") or str(client_database).startswith("https://")
        ):
            self.key_resolver = UrlKeyResolver(client_database_base_url=str(client_database), key_cache=key_cache)
        elif client_database:
            self.key_resolver = FileKeyResolver(client_database_directory=str(client_database), key_cache=key_cache)
        else:
            raise ValueError("No key resolver nor client database specified")
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
        alg = self.get_algorithm(request.headers)
        signature_algorithm = supported_signature_algorithms[alg]
        verifier = HTTPMessageVerifier(
            signature_algorithm=signature_algorithm,
            key_resolver=self.key_resolver,
        )
        try:
            results = verifier.verify(request)
        except KeyError as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown HTTP signature key") from exc
        except InvalidSignature as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid HTTP signature") from exc
        except Exception as exc:
            self.logger.warning("Unable to verify HTTP signature", exc_info=exc)
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unable to verify HTTP signature") from exc

        for result in results:
            try:
                await self.verify_content_digest(result, request)
                self.logger.debug("Content-Digest verified")
                return result
            except InvalidContentDigest as exc:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Content-Digest verification failed") from exc
            except UnsupportedContentDigestAlgorithm:
                self.logger.debug("Unsupported Content-Digest algorithm")
            except ContentDigestMissing:
                self.logger.debug("Content-Digest header missing")

        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unable to verify Content-Digest")


def rfc_3339_datetime_now() -> str:
    """Return current time(UTC) as ISO 8601 timestamp"""
    return str(datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))


def pendulum_as_datetime(dt: pendulum.DateTime) -> datetime:
    return datetime(
        year=dt.year,
        month=dt.month,
        day=dt.day,
        hour=dt.hour,
        minute=dt.minute,
        second=dt.second,
        microsecond=dt.microsecond,
        tzinfo=dt.tzinfo,
    )
