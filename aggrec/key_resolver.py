from abc import abstractmethod
from urllib.parse import urljoin

import httpx
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from http_message_signatures import HTTPSignatureKeyResolver
from opentelemetry import metrics, trace
from werkzeug.utils import safe_join

from .key_cache import KeyCache

tracer = trace.get_tracer("aggrec.tracer")
meter = metrics.get_meter("aggrec.meter")


public_key_get_counter = meter.create_counter(
    "aggregates.public_key_get_counter",
    description="The number of public key lookups",
)


class CacheKeyResolver(HTTPSignatureKeyResolver):
    def __init__(self, key_cache: KeyCache | None):
        self.key_cache = key_cache

    @abstractmethod
    def get_public_key_pem(self, key_id: str) -> bytes:
        pass

    def resolve_public_key(self, key_id: str):
        with tracer.start_as_current_span("resolve_public_key"):
            if self.key_cache:
                public_key_pem = self.key_cache.get(key_id)
                if not public_key_pem:
                    public_key_pem = self.get_public_key_pem(key_id)
                    self.key_cache.set(key_id, public_key_pem)
                    public_key_get_counter.add(1)
            else:
                public_key_pem = self.get_public_key_pem(key_id)
        return load_pem_public_key(public_key_pem)


class FileKeyResolver(CacheKeyResolver):
    def __init__(self, client_database_directory: str, key_cache: KeyCache | None = None):
        super().__init__(key_cache=key_cache)
        self.client_database_directory = client_database_directory

    def get_public_key_pem(self, key_id: str) -> bytes:
        with tracer.start_as_current_span("get_public_key_pem_from_file"):
            filename = safe_join(self.client_database_directory, f"{key_id}.pem")
            try:
                with open(filename, "rb") as fp:
                    return fp.read()
            except FileNotFoundError as exc:
                raise KeyError(key_id) from exc


class UrlKeyResolver(CacheKeyResolver):
    def __init__(self, client_database_base_url: str, key_cache: KeyCache | None = None):
        super().__init__(key_cache=key_cache)
        self.client_database_base_url = client_database_base_url
        self.httpx_client = httpx.Client()

    def get_public_key_pem(self, key_id: str) -> bytes:
        with tracer.start_as_current_span("get_public_key_pem_from_url"):
            public_key_url = urljoin(self.client_database_base_url, f"{key_id}.pem")
            try:
                response = self.httpx_client.get(public_key_url)
                response.raise_for_status()
                return response.content
            except httpx.HTTPError as exc:
                raise KeyError(key_id) from exc
