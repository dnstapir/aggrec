import logging
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address

import aniso8601
import http_sf
from fastapi import HTTPException, Request, status
from http_message_signatures import HTTPMessageVerifier, HTTPSignatureKeyResolver, VerifyResult, algorithms
from http_message_signatures.digests import ContentDigest
from http_message_signatures.exceptions import InvalidSignature

from dnstapir.key_resolver import KeyResolver, PublicKey

SUPPORTED_SIGNATURE_ALGORITHMS: dict[str, type] = {
    algorithm_cls.algorithm_id: algorithm_cls
    for algorithm_cls in [
        algorithms.RSA_PSS_SHA512,
        algorithms.RSA_V1_5_SHA256,
        algorithms.ED25519,
        algorithms.ECDSA_P256_SHA256,
    ]
}


def validate_signature_algorithm(alg: str) -> str:
    """Validate that the given signature algorithm is supported."""

    if alg not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise ValueError("Unsupported signature algorithm")
    return alg


async def read_body_with_limit(request: Request, max_length: int | None) -> bytes:
    """Read request body, aborting with 413 as soon as it exceeds max_length"""

    chunks: list[bytes] = []
    length = 0

    async for chunk in request.stream():
        chunks.append(chunk)
        length += len(chunk)
        if max_length is not None and length > max_length:
            raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "Content length exceeds the maximum allowed")

    return b"".join(chunks)


class CustomHTTPSignatureKeyResolver(HTTPSignatureKeyResolver):
    def __init__(self, key_resolver: KeyResolver):
        self.key_resolver = key_resolver

    def resolve_public_key(self, key_id: str) -> PublicKey:
        return self.key_resolver.resolve_public_key(key_id=key_id)


class RequestVerifier:
    def __init__(
        self,
        key_resolver: KeyResolver,
        default_algorithm: str | None = None,
        accepted_algorithms: Iterable[str] | None = None,
        require_components: Iterable[str] | None = None,
        max_content_length: int | None = None,
    ):
        self.http_key_resolver = CustomHTTPSignatureKeyResolver(key_resolver)
        self.require_components: set[str] = {f'"{component}"' for component in (require_components or [])}
        self.logger = logging.getLogger(__name__).getChild(self.__class__.__name__)
        self.max_content_length = max_content_length
        self.default_algorithm = default_algorithm
        self.accepted_algorithms = set(accepted_algorithms) if accepted_algorithms is not None else None

    @staticmethod
    def get_algorithm(headers: dict) -> str | None:
        parse_signature_input = http_sf.parse(headers["signature-input"].encode(), tltype="dictionary")
        for _label, values in parse_signature_input.items():
            for item in values:
                if isinstance(item, dict) and (alg := item.get("alg")) and isinstance(alg, str):
                    return str(alg)
        return

    async def verify(self, request: Request) -> tuple[VerifyResult, bytes]:
        """Verify request and return signer"""

        logger_extra = {
            "http_request_method": request.method,
            "http_request_url": request.url,
            "http_request_headers": request.headers,
        }

        self.logger.debug("Verify HTTP request", extra=logger_extra)

        try:
            alg = self.get_algorithm(request.headers)
        except KeyError as exc:
            msg = "Signature-Input header missing"
            self.logger.warning(msg, extra=logger_extra)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, msg) from exc
        except http_sf.StructuredFieldError as exc:
            msg = "Invalid Signature-Input header"
            self.logger.warning(msg, extra=logger_extra, exc_info=exc)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, msg) from exc

        signature_algorithm = SUPPORTED_SIGNATURE_ALGORITHMS.get(alg) or SUPPORTED_SIGNATURE_ALGORITHMS.get(
            self.default_algorithm
        )

        if not signature_algorithm or (
            self.accepted_algorithms is not None and signature_algorithm.algorithm_id not in self.accepted_algorithms
        ):
            msg = "Unsupported signature algorithm"
            self.logger.warning(msg, extra=logger_extra)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, msg)

        verifier = HTTPMessageVerifier(
            signature_algorithm=signature_algorithm,
            key_resolver=self.http_key_resolver,
        )

        try:
            results = verifier.verify(request, require_components=list(self.require_components))
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

        content = await read_body_with_limit(request, self.max_content_length)

        for result in results:
            try:
                if ContentDigest.verify_components(result.covered_components, content):
                    self.logger.debug("Content-Digest verified")
                    return result, content
            except InvalidSignature as exc:
                msg = "Content-Digest verification failed"
                self.logger.warning(msg, extra=logger_extra, exc_info=exc)
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, msg) from exc
            self.logger.debug("Content-Digest not covered by signature")

        msg = "Unable to verify Content-Digest"
        self.logger.warning(msg, extra=logger_extra)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, msg)


def rfc_3339_datetime_now() -> str:
    """Return current time(UTC) as ISO 8601 timestamp"""
    return str(datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))


def parse_iso8601_interval(interval: str) -> tuple[datetime, timedelta]:
    """Parse ISO8601 interval and return resulting datetime and timedelta"""
    t1, t2 = aniso8601.parse_interval(interval)
    if not isinstance(t1, datetime) or not isinstance(t2, datetime):
        raise ValueError("Invalid interval format")
    if t1.tzinfo is None:
        raise ValueError("Start time must include timezone")
    if t2.tzinfo is None:
        raise ValueError("End time must include timezone")
    t1 = t1.astimezone(UTC)
    t2 = t2.astimezone(UTC)
    duration = timedelta(seconds=(t2 - t1).total_seconds())
    if duration.total_seconds() < 0:
        raise ValueError("Duration cannot be negative")
    return t1, duration


def check_client_access(
    request: Request,
    allowed_networks: list[IPv4Address | IPv6Address | IPv4Network | IPv6Network],
) -> None:
    """Check if client IP is allowed to access the resource"""

    if request.client and request.client.host:
        try:
            client_address = ip_address(request.client.host)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid client IP address: {request.client.host}",
            ) from exc

        for entry in allowed_networks:
            if (isinstance(entry, IPv4Address | IPv6Address) and client_address == entry) or (
                isinstance(entry, IPv4Network | IPv6Network) and client_address in entry
            ):
                logging.debug("Allowed access for client %s", client_address)
                return

        logging.warning("Denied access for client %s", client_address)
    else:
        logging.warning("Denied access for unknown client")

    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
