import logging

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from flask import Request
from http_message_signatures import (
    HTTPMessageVerifier,
    HTTPSignatureKeyResolver,
    algorithms,
)
from http_message_signatures.exceptions import InvalidSignature
from werkzeug.exceptions import BadRequest, InternalServerError, Unauthorized
from werkzeug.utils import safe_join


class MyHTTPSignatureKeyResolver(HTTPSignatureKeyResolver):
    def __init__(self, client_database: str):
        self.client_database = client_database

    def resolve_public_key(self, key_id: str):
        filename = safe_join(self.client_database, f"{key_id}.pem")
        try:
            with open(filename, "rb") as fp:
                return load_pem_public_key(fp.read())
        except FileNotFoundError as exc:
            raise KeyError(key_id)


class RequestVerifier:
    def __init__(self, client_database: str):
        self.algorithm = algorithms.ECDSA_P256_SHA256
        self.key_resolver = MyHTTPSignatureKeyResolver(client_database)
        self.logger = logging.getLogger(__name__).getChild(self.__class__.__name__)

    def verify(self, request: Request) -> dict:
        """Verify request and return signer"""
        verifier = HTTPMessageVerifier(
            signature_algorithm=self.algorithm,
            key_resolver=self.key_resolver,
        )
        try:
            results = verifier.verify(request)
        except KeyError as exc:
            self.logger.warning("Unknown HTTP signature key: %s", str(exc))
            raise Unauthorized
        except InvalidSignature:
            self.logger.warning("Invalid HTTP signature")
            raise Unauthorized
        except Exception as exc:
            self.logger.warning("Unable to verify HTTP signature")
            raise BadRequest
        if len(results) == 0:
            self.logger.error("No results")
            raise InternalServerError
        # TOOD: handle multiple signatures
        return results[0].parameters
