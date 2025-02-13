import asyncio
import base64
import hashlib
import json
import logging
import re
import uuid
from contextlib import suppress
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated
from urllib.parse import urljoin

import bson
import pymongo
from bson.objectid import ObjectId
from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse
from opentelemetry import metrics, trace
from pydantic import BaseModel, Field

from aggrec.helpers import RequestVerifier

from .db_models import AggregateMetadata
from .helpers import parse_iso8601_interval, rfc_3339_datetime_now
from .settings import Settings

logger = logging.getLogger(__name__)

tracer = trace.get_tracer("aggrec.tracer")
meter = metrics.get_meter("aggrec.meter")

aggregates_counter = meter.create_counter(
    "aggregates.counter",
    description="The number of aggregates stored",
)

aggregates_by_creator_counter = meter.create_counter(
    "aggregates.counter_by_creator",
    description="The number of aggregates per creator",
)

aggregates_duplicates_counter = meter.create_counter(
    "aggregates.duplicates_counter",
    description="The number of duplicate aggregates received",
)

aggregates_mqtt_queue_drops = meter.create_counter(
    "aggregates.mqtt_queue_drops",
    description="MQTT messages dropped due to full queue",
)

aggregates_nats_queue_drops = meter.create_counter(
    "aggregates.nats_queue_drops",
    description="NATS messages dropped due to full queue",
)


METADATA_HTTP_HEADERS = [
    "User-Agent",
    "Content-Length",
    "Content-Type",
    "Content-Digest",
    "Content-Encoding",
    "Signature",
    "Signature-Input",
]

router = APIRouter()


class AggregateType(str, Enum):
    histogram = "histogram"
    vector = "vector"


class AggregateContentType(str, Enum):
    parquet = "application/vnd.apache.parquet"
    binary = "application/binary"


class AggregateMetadataResponse(BaseModel):
    aggregate_id: str = Field(title="Aggregate identifier", example="3b241101-e2bb-4255-8caf-4136c566a962")
    aggregate_type: AggregateType = Field(title="Aggregate type", example="application/vnd.apache.parquet")
    created: datetime = Field(title="Aggregate creation timestamp")
    creator: str = Field(title="Aggregate creator")
    headers: dict = Field(title="Dictionary of relevant HTTP headers")
    content_type: str = Field(title="Content MIME type")
    content_length: int = Field(title="Content length")
    content_location: str = Field(title="Content location (URL)")
    s3_bucket: str = Field(title="S3 bucket name")
    s3_object_key: str = Field(title="S3 object key")
    aggregate_interval_start: datetime | None = Field(default=None, title="Aggregate interval start")
    aggregate_interval_duration: int | None = Field(default=None, title="Aggregate interval duration (seconds)")

    @classmethod
    def from_db_model(cls, metadata: AggregateMetadata, settings: Settings):
        aggregate_id = str(metadata.id)
        return cls(
            aggregate_id=aggregate_id,
            aggregate_type=metadata.aggregate_type.value,
            aggregate_interval_start=metadata.aggregate_interval_start,
            aggregate_interval_duration=metadata.aggregate_interval_duration,
            created=metadata.id.generation_time,
            creator=str(metadata.creator),
            headers=metadata.http_headers,
            content_type=metadata.content_type,
            content_length=metadata.content_length,
            content_location=urljoin(
                str(settings.metadata_base_url),
                f"/api/v1/aggregates/{aggregate_id}/payload",
            ),
            s3_bucket=metadata.s3_bucket,
            s3_object_key=metadata.s3_object_key,
        )


def get_http_headers(request: Request, covered_components_headers: list[str]) -> dict[str, str]:
    """Get dictionary of relevant metadata HTTP headers"""

    relevant_headers = set([header.lower() for header in METADATA_HTTP_HEADERS])

    for header in covered_components_headers:
        if match := re.match(r"^\"([^@].+)\"$", header):
            relevant_headers.add(match.group(1))

    res = {}
    for header in relevant_headers:
        if value := request.headers.get(header):
            res[header] = value
    return res


def get_aggregate_location(aggregate_id: ObjectId) -> str:
    """Get aggregate location"""
    return f"/api/v1/aggregates/{aggregate_id}"


def get_new_aggregate_event_message(metadata: AggregateMetadata, settings: Settings) -> dict:
    """Get new aggregate event message"""
    return {
        "$schema": "https://schema.dnstapir.se/v1/new_aggregate",
        "version": 1,
        "message_id": str(uuid.uuid4()),
        "timestamp": rfc_3339_datetime_now(),
        "type": "new_aggregate",
        "aggregate_id": str(metadata.id),
        "aggregate_type": metadata.aggregate_type.value,
        "created": metadata.id.generation_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "creator": str(metadata.creator),
        "metadata_location": urljoin(
            str(settings.metadata_base_url),
            f"/api/v1/aggregates/{metadata.id}",
        ),
        "content_location": urljoin(
            str(settings.metadata_base_url),
            f"/api/v1/aggregates/{metadata.id}/payload",
        ),
        "s3_bucket": metadata.s3_bucket,
        "s3_object_key": metadata.s3_object_key,
        **(
            {
                "aggregate_interval_start": metadata.aggregate_interval_start.astimezone(tz=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "aggregate_interval_duration": metadata.aggregate_interval_duration,
            }
            if metadata.aggregate_interval_start and metadata.aggregate_interval_duration
            else {}
        ),
    }


def get_s3_object_key(metadata: AggregateMetadata) -> str:
    """Get S3 object key from metadata"""
    dt = metadata.id.generation_time
    dt = dt.astimezone(tz=timezone.utc)
    fields_dict = {
        "type": metadata.aggregate_type.name.lower(),
        "year": f"{dt.year:04}",
        "month": f"{dt.month:02}",
        "day": f"{dt.day:02}",
        "hour": f"{dt.hour:02}",
        "minute": f"{dt.minute:02}",
        "second": f"{dt.second:02}",
        "creator": metadata.creator,
        "id": metadata.id,
    }
    fields_list = [f"{k}={v}" for k, v in fields_dict.items() if v is not None]
    return "/".join(fields_list)


def get_s3_object_metadata(metadata: AggregateMetadata) -> dict:
    """Get S3 object metadata from metadata"""
    return {
        "aggregate-id": str(metadata.id),
        "aggregate-type": metadata.aggregate_type.value,
        "created": metadata.id.generation_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "creator": str(metadata.creator),
        **(
            {
                "interval-start": metadata.aggregate_interval_start.astimezone(tz=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "interval-duration": str(metadata.aggregate_interval_duration),
            }
            if metadata.aggregate_interval_start and metadata.aggregate_interval_duration
            else {}
        ),
    }


@router.post(
    "/api/v1/aggregate/{aggregate_type}",
    status_code=201,
    responses={
        201: {
            "description": "Aggregate created",
            "content": None,
            "headers": {
                "location": {
                    "description": "Aggregate URL",
                    "schema": {"type": "string", "format": "uri"},
                },
            },
        }
    },
    tags=["client"],
)
async def create_aggregate(
    aggregate_type: AggregateType,
    content_type: Annotated[AggregateContentType, Header()],
    aggregate_interval: Annotated[
        str | None,
        Header(
            description="Aggregate window as an ISO 8601 time interval (start and duration)",
            example="1984-01-01T12:00:00Z/PT1M",
        ),
    ],
    content_digest: Annotated[
        str,
        Header(title="RFC 9530 Digest"),
    ],
    content_length: Annotated[
        int,
        Header(title="RFC 9112 Content Length"),
    ],
    signature: Annotated[
        str,
        Header(
            title="RFC 9421 Signature",
            description="""
The following HTTP headers MUST be signed:

- Content-Length
- Content-Type
- Content-Digest

Derived components MUST NOT be included in the signature input.
""",
        ),
    ],
    signature_input: Annotated[
        str,
        Header(title="RFC 9421 Signature Input"),
    ],
    request: Request,
):
    span = trace.get_current_span()

    with tracer.start_as_current_span("http_request_verifier"):
        http_request_verifier = RequestVerifier(key_resolver=request.app.key_resolver)
        res = await http_request_verifier.verify(request)

    creator = res.parameters.get("keyid")
    logger.info("Create aggregate request by keyid=%s", creator)

    http_headers = get_http_headers(request, res.covered_components.keys())

    # if we receive an aggregate already seen, return existing metadata
    if metadata := AggregateMetadata.objects(content_digest=content_digest).first():
        logger.warning("Received duplicate aggregate from %s", creator)
        aggregates_duplicates_counter.add(1, {"aggregate_type": aggregate_type.value, "creator": creator})
        metadata_location = get_aggregate_location(metadata.id)
        return Response(status_code=status.HTTP_201_CREATED, headers={"Location": metadata_location})

    aggregate_id = ObjectId()
    metadata_location = get_aggregate_location(aggregate_id)

    span.set_attribute("aggregate.id", str(aggregate_id))
    span.set_attribute("aggregate.type", aggregate_type.value)
    span.set_attribute("aggregate.creator", creator)

    s3_bucket = request.app.settings.s3.get_bucket_name()

    if aggregate_interval:
        try:
            aggregate_interval_start, aggregate_interval_timedelta = parse_iso8601_interval(aggregate_interval)
            aggregate_interval_duration = aggregate_interval_timedelta.total_seconds()
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "Invalid Aggregate-Interval: must be an ISO 8601 time interval (e.g., '2024-01-01T12:00:00Z/PT1M')",
            ) from exc
    else:
        aggregate_interval_start = None
        aggregate_interval_duration = None

    metadata = AggregateMetadata(
        id=aggregate_id,
        aggregate_type=aggregate_type,
        aggregate_interval_start=aggregate_interval_start,
        aggregate_interval_duration=aggregate_interval_duration,
        creator=creator,
        http_headers=http_headers,
        content_type=content_type,
        content_digest=content_digest,
        s3_bucket=s3_bucket,
    )

    content = await request.body()
    content_checksum = base64.b64encode(hashlib.sha256(content).digest()).decode()

    metadata.content_length = len(content)
    metadata.s3_object_key = get_s3_object_key(metadata)

    s3_object_metadata = get_s3_object_metadata(metadata)
    logger.debug("S3 object metadata: %s", s3_object_metadata)

    async with request.app.get_s3_client() as s3_client:
        if request.app.settings.s3.create_bucket:
            with suppress(Exception):
                await s3_client.create_bucket(Bucket=s3_bucket)

        with tracer.start_as_current_span("s3.put_object"):
            await s3_client.put_object(
                Bucket=s3_bucket,
                Key=metadata.s3_object_key,
                Metadata=s3_object_metadata,
                ContentType=content_type,
                ContentLength=metadata.content_length,
                ChecksumAlgorithm="SHA-256",
                ChecksumSHA256=content_checksum,
                Body=content,
            )
        logger.info("Object created: %s", metadata.s3_object_key)

        with tracer.start_as_current_span("mongodb.insert"):
            try:
                with pymongo.timeout(2):
                    metadata.save(request.app.settings.mongodb.timeout)
                logger.info("Metadata saved: %s", metadata.id)
            except Exception as exc:
                logger.error("Failed to save metadata, deleting object %s", metadata.s3_object_key, exc_info=exc)
                await s3_client.delete_object(Bucket=s3_bucket, Key=metadata.s3_object_key)
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error") from exc

    aggregates_counter.add(1, {"aggregate_type": aggregate_type.value})
    aggregates_by_creator_counter.add(1, {"aggregate_type": aggregate_type.value, "creator": creator})

    message_payload = json.dumps(get_new_aggregate_event_message(metadata, request.app.settings))

    if request.app.mqtt_new_aggregate_messages is not None:
        try:
            request.app.mqtt_new_aggregate_messages.put_nowait(message_payload)
            logger.debug("New aggregate message added to MQTT queue")
        except asyncio.QueueFull:
            aggregates_mqtt_queue_drops.add(1)
            logger.warning("MQTT queue full, message dropped")

    if request.app.nats_new_aggregate_messages is not None:
        try:
            request.app.nats_new_aggregate_messages.put_nowait(message_payload)
            logger.debug("New aggregate message added to NATS queue")
        except asyncio.QueueFull:
            aggregates_nats_queue_drops.add(1)
            logger.warning("NATS queue full, message dropped")

    return Response(status_code=status.HTTP_201_CREATED, headers={"Location": metadata_location})


@router.get(
    "/api/v1/aggregates/{aggregate_id}",
    responses={
        200: {"model": AggregateMetadataResponse},
        404: {},
    },
    tags=["backend"],
)
def get_aggregate_metadata(
    aggregate_id: str,
    request: Request,
) -> AggregateMetadataResponse:
    try:
        aggregate_object_id = ObjectId(aggregate_id)
    except bson.errors.InvalidId as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND) from exc

    if metadata := AggregateMetadata.objects(id=aggregate_object_id).first():
        return AggregateMetadataResponse.from_db_model(metadata, request.app.settings)

    raise HTTPException(status.HTTP_404_NOT_FOUND)


@router.get(
    "/api/v1/aggregates/{aggregate_id}/payload",
    responses={
        200: {
            "description": "Aggregate payload",
            "headers": {
                "link": {
                    "description": 'Linked resources (RFC 8288), rel="about" for metadata URL',
                    "schema": {"type": "string", "format": "uri"},
                },
            },
            "content": {
                "application/vnd.apache.parquet": {},
                "application/binary": {},
            },
        },
        404: {},
    },
    tags=["backend"],
)
async def get_aggregate_payload(
    aggregate_id: str,
    request: Request,
) -> bytes:
    try:
        aggregate_object_id = ObjectId(aggregate_id)
    except bson.errors.InvalidId as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND) from exc

    if metadata := AggregateMetadata.objects(id=aggregate_object_id).first():
        with tracer.start_as_current_span("s3.get_object"):
            async with request.app.get_s3_client() as s3_client:
                s3_obj = await s3_client.get_object(Bucket=metadata.s3_bucket, Key=metadata.s3_object_key)

        metadata_location = get_aggregate_location(metadata.id)

        return StreamingResponse(
            content=s3_obj["Body"],
            media_type=metadata.content_type,
            headers={
                "Link": f'{metadata_location}; rel="about"',
                # "Content-Length": str(metadata.content_length),
            },
        )

    raise HTTPException(status.HTTP_404_NOT_FOUND)
