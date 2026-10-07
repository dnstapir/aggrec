import asyncio
import hashlib
import os
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import http_sf
import httpx2
import pytest
from aiobotocore.response import AioStreamingBody
from fastapi import status
from fastapi.testclient import TestClient
from http_message_signatures import HTTPMessageSigner, HTTPSignatureKeyResolver, algorithms

from aggrec.server import AggrecServer
from aggrec.settings import Settings
from tests.test_http_signatures import TestHTTPSignatureKeyResolver

USER_AGENT = "pytest/0.0"

CLIENT_IP_ADDRESS = "127.0.0.1"
CLIENT_IP_PORT = 4242


# Set test configuration file - note that environment variables with AGGREC_ prefix
# will take precedence over values in this file
with patch.dict(os.environ, {"AGGREC_CONFIG": "tests/test.toml"}):
    settings = Settings()


def get_mock_s3_client() -> MagicMock:
    """Return a mock replacement for AggrecServer.get_s3_client"""
    objects: dict[tuple[str, str], bytes] = {}

    async def create_bucket(Bucket: str) -> None:
        return None

    async def put_object(Bucket: str, Key: str, Body: bytes, **kwargs) -> None:
        objects[(Bucket, Key)] = Body
        return None

    async def get_object(Bucket: str, Key: str) -> dict[str, Any]:
        data = objects[(Bucket, Key)]
        content = aiohttp.StreamReader(MagicMock(), limit=2**16, loop=asyncio.get_running_loop())
        content.feed_data(data)
        content.feed_eof()
        body = AioStreamingBody(MagicMock(content=content), content_length=len(data))
        return {"Body": body, "ContentLength": len(data)}

    s3_client = AsyncMock()
    s3_client.__aenter__.return_value = s3_client
    s3_client.create_bucket.side_effect = create_bucket
    s3_client.put_object.side_effect = put_object
    s3_client.get_object.side_effect = get_object
    return MagicMock(return_value=s3_client)


def get_test_client(resolver: HTTPSignatureKeyResolver) -> TestClient:
    app = AggrecServer(settings)
    app.key_resolver = resolver
    app.connect_mongodb()
    app.get_s3_client = get_mock_s3_client()
    return TestClient(app, client=(CLIENT_IP_ADDRESS, CLIENT_IP_PORT), headers={"User-Agent": USER_AGENT})


def get_signed_request(
    client: TestClient,
    url: str,
    headers: dict[str, str],
    content: bytes,
    key_resolver: HTTPSignatureKeyResolver,
    key_id: str,
    covered_component_ids: list[str] | None = None,
) -> httpx2.Request:
    """Create signed request"""

    if covered_component_ids is None:
        covered_component_ids = ["content-type", "content-digest", "content-length"]

    request = client.build_request("POST", url, content=content, headers=headers)
    request.headers["X-Request-ID"] = str(uuid.uuid4())
    request.headers["Content-Type"] = "application/binary"
    request.headers["Content-Digest"] = http_sf.ser({"sha-256": hashlib.sha256(request.content).digest()})

    signer = HTTPMessageSigner(signature_algorithm=key_resolver.algorithm, key_resolver=key_resolver)
    signer.sign(
        request,
        key_id=key_id,
        label="client",
        covered_component_ids=covered_component_ids,
        include_alg=True,
    )

    return request


def test_create_aggrec_signed():
    """Create aggregate histogram signed request including the aggregate interval in the covered components."""

    algorithm = algorithms.ED25519
    key_id = "test"
    key_resolver = TestHTTPSignatureKeyResolver(key_id=key_id, algorithm=algorithm)

    client = get_test_client(key_resolver)
    server = ""

    content = os.urandom(1024)

    request = get_signed_request(
        client=client,
        url=f"{server}/api/v1/aggregate/histogram",
        headers={
            "Aggregate-Interval": "1984-01-01T12:00:00Z/PT1M",
        },
        content=content,
        key_resolver=key_resolver,
        key_id=key_id,
        covered_component_ids=["content-type", "content-digest", "content-length", "aggregate-interval"],
    )

    response = client.send(request)
    assert response.status_code == status.HTTP_201_CREATED

    s3_client = client.app.get_s3_client.return_value
    s3_client.put_object.assert_awaited_once()
    assert s3_client.put_object.await_args.kwargs["Body"] == request.content

    aggregate_location = response.headers.get("Location")
    assert aggregate_location is not None

    response = client.get(aggregate_location)
    assert response.status_code == status.HTTP_200_OK

    response = client.get(f"{aggregate_location}/payload")
    assert response.status_code == status.HTTP_200_OK
    assert response.content == content


def test_create_aggrec_signed_no_interval():
    """Create aggregate histogram signed request without including the aggregate interval in the covered components."""

    algorithm = algorithms.ED25519
    key_id = "test"
    key_resolver = TestHTTPSignatureKeyResolver(key_id=key_id, algorithm=algorithm)

    client = get_test_client(key_resolver)
    server = ""

    content = os.urandom(1024)

    request = get_signed_request(
        client=client,
        url=f"{server}/api/v1/aggregate/histogram",
        headers={
            "Aggregate-Interval": "1984-01-01T12:00:00Z/PT1M",
        },
        content=content,
        key_resolver=key_resolver,
        key_id=key_id,
        covered_component_ids=["content-type", "content-digest", "content-length"],
    )

    response = client.send(request)
    assert response.status_code == status.HTTP_201_CREATED

    s3_client = client.app.get_s3_client.return_value
    s3_client.put_object.assert_awaited_once()
    assert s3_client.put_object.await_args.kwargs["Body"] == request.content


def test_get_payload_s3_read_timeout():
    """Abort payload streaming when a read from S3 stalls."""

    algorithm = algorithms.ED25519
    key_id = "test"
    key_resolver = TestHTTPSignatureKeyResolver(key_id=key_id, algorithm=algorithm)

    client = get_test_client(key_resolver)
    server = ""

    content = os.urandom(1024)

    request = get_signed_request(
        client=client,
        url=f"{server}/api/v1/aggregate/histogram",
        headers={
            "Aggregate-Interval": "1984-01-01T12:00:00Z/PT1M",
        },
        content=content,
        key_resolver=key_resolver,
        key_id=key_id,
    )

    response = client.send(request)
    assert response.status_code == status.HTTP_201_CREATED
    aggregate_location = response.headers["Location"]

    async def get_object_stalled(Bucket: str, Key: str) -> dict[str, Any]:
        # Deliver half of the payload, then never send more data nor EOF
        stream = aiohttp.StreamReader(MagicMock(), limit=2**16, loop=asyncio.get_running_loop())
        stream.feed_data(content[: len(content) // 2])
        body = AioStreamingBody(MagicMock(content=stream), content_length=len(content))
        return {"Body": body, "ContentLength": len(content)}

    s3_client = client.app.get_s3_client.return_value
    s3_client.get_object.side_effect = get_object_stalled
    s3_client.__aexit__.reset_mock()

    with patch.object(client.app.settings.s3, "chunk_timeout", 0.1), pytest.raises(TimeoutError):
        client.get(f"{aggregate_location}/payload")

    s3_client.__aexit__.assert_awaited_once()


def test_create_aggrec_unsigned():
    """Create aggregate histogram unsigned request."""

    algorithm = algorithms.ED25519
    key_id = "test"
    key_resolver = TestHTTPSignatureKeyResolver(key_id=key_id, algorithm=algorithm)

    client = get_test_client(key_resolver)
    server = ""

    content = os.urandom(1024)

    response = client.post(f"{server}/api/v1/aggregate/histogram", content=content)
    assert response.status_code == 422

    s3_client = client.app.get_s3_client.return_value
    s3_client.put_object.assert_not_awaited()


def test_stats():

    algorithm = algorithms.ED25519
    key_id = "test"
    key_resolver = TestHTTPSignatureKeyResolver(key_id=key_id, algorithm=algorithm)

    client = get_test_client(key_resolver)
    server = ""

    response = client.get(f"{server}/api/v1/stats/creators")
    assert response.status_code == 200

    response = client.get(f"{server}/api/v1/stats/aggregates")
    assert response.status_code == 200
