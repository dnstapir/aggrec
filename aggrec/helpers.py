import logging

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from flask import Request
from http_message_signatures import (
    HTTPMessageVerifier,
    HTTPSignatureKeyResolver,
    algorithms,
)
from werkzeug.exceptions import BadRequest, InternalServerError


class MyHTTPSignatureKeyResolver(HTTPSignatureKeyResolver):
    def resolve_public_key(self, key_id: str):
        with open(f"{key_id}.pem", "rb") as fh:
            return load_pem_public_key(fh.read())


class RequestVerifier:
    def __init__(self):
        self.algorithm = algorithms.ECDSA_P256_SHA256
        self.key_resolver = MyHTTPSignatureKeyResolver()
        self.logger = logging.getLogger(__name__).getChild(self.__class__.__name__)

    def verify(self, request: Request) -> dict:
        """Verify request and return signer"""
        verifier = HTTPMessageVerifier(
            signature_algorithm=self.algorithm,
            key_resolver=self.key_resolver,
        )
        try:
            results = verifier.verify(request)
        except Exception:
            msg = "Unable to verify HTTP signature"
            self.logger.warning(msg)
            raise BadRequest(msg)
        if len(results) == 0:
            self.logger.error("No results")
            raise InternalServerError
        # TOOD: handle multiple signatures
        return results[0].parameters
