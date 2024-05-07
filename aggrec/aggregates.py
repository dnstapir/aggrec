import json
import logging
import re
from contextlib import suppress
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Dict, List
from urllib.parse import urljoin

import aiobotocore.session
import aiomqtt
import boto3
import bson
import pendulum
from bson.objectid import ObjectId
from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from aggrec.helpers import RequestVerifier

from .db_models import AggregateMetadata
from .helpers import pendulum_as_datetime, rfc_3339_datetime_now
from .settings import Settings

logger = logging.getLogger(__name__)


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
    aggregate_id: str = Field(title="Aggregate identifier")
    aggregate_type: AggregateType = Field(title="Aggregate type")
    created: datetime = Field(title="Aggregate creation timestamp")
    creator: str = Field(title="Aggregate creator")
    headers: dict = Field(title="Dictionary of relevant HTTP headers")
    content_type: str = Field(title="Content MIME type")
    content_length: int = Field(title="Content length")
    content_location: str = Field(title="Content location (URL)")
    s3_bucket: str = Field(title="S3 bucket name")
    s3_object_key: str = Field(title="S3 object key")
    aggregate_interval_start: datetime | None = Field(
        default=None, title="Aggregate interval start"
    )
    aggregate_interval_duration: int | None = Field(
        default=None, title="Aggregate interval duration (seconds)"
    )

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
                settings.metadata_base_url,
                f"/api/v1/aggregates/{aggregate_id}/payload",
            ),
            s3_bucket=metadata.s3_bucket,
            s3_object_key=metadata.s3_object_key,
        )


def get_http_headers(
    request: Request, covered_components_headers: List[str]
) -> Dict[str, str]:
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


def get_s3_client(settings: Settings):
    return aiobotocore.session.AioSession().create_client(
        "s3",
        endpoint_url=settings.s3_endpoint_url,
        aws_access_key_id=settings.s3_access_key_id,
        aws_secret_access_key=settings.s3_secret_access_key,
        aws_session_token=None,
        config=boto3.session.Config(signature_version="s3v4"),
    )


def get_new_aggregate_event_message(
    metadata: AggregateMetadata, settings: Settings
) -> dict:
    """Get new aggregate event message"""
    return {
        "version": 1,
        "timestamp": rfc_3339_datetime_now(),
        "type": "new_aggregate",
        "aggregate_id": str(metadata.id),
        "aggregate_type": metadata.aggregate_type.value,
        "created": metadata.id.generation_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "creator": str(metadata.creator),
        "metadata_location": urljoin(
            settings.metadata_base_url,
            f"/api/v1/aggregates/{metadata.id}",
        ),
        "content_location": urljoin(
            settings.metadata_base_url,
            f"/api/v1/aggregates/{metadata.id}/payload",
        ),
        "s3_bucket": metadata.s3_bucket,
        "s3_object_key": metadata.s3_object_key,
        **(
            {
                "aggregate_interval_start": metadata.aggregate_interval_start.astimezone(
                    tz=timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "aggregate_interval_duration": metadata.aggregate_interval_duration,
            }
            if metadata.aggregate_interval_start
            and metadata.aggregate_interval_duration
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
                "interval-start": metadata.aggregate_interval_start.astimezone(
                    tz=timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "interval-duration": str(metadata.aggregate_interval_duration),
            }
            if metadata.aggregate_interval_start
            and metadata.aggregate_interval_duration
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
    http_request_verifier = RequestVerifier(
        client_database=request.app.settings.clients_database
    )
    res = await http_request_verifier.verify(request)

    creator = res.parameters.get("keyid")
    logger.info("Create aggregate request by keyid=%s", creator)

    http_headers = get_http_headers(request, res.covered_components.keys())

    aggregate_id = ObjectId()
    location = f"/api/v1/aggregates/{aggregate_id}"

    s3_bucket = request.app.settings.s3_bucket

    if aggregate_interval:
        period = pendulum.parse(aggregate_interval)
        if not isinstance(period, pendulum.Interval):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid Aggregate-Interval"
            )
        aggregate_interval_start = pendulum_as_datetime(period.start)
        aggregate_interval_duration = period.start.diff(period.end).in_seconds()
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
        s3_bucket=s3_bucket,
    )

    content = await request.body()

    metadata.content_length = len(content)
    metadata.s3_object_key = get_s3_object_key(metadata)

    s3_object_metadata = get_s3_object_metadata(metadata)
    logger.debug("S3 object metadata: %s", s3_object_metadata)

    async with get_s3_client(request.app.settings) as s3_client:
        if request.app.settings.s3_bucket_create:
            with suppress(Exception):
                await s3_client.create_bucket(Bucket=s3_bucket)

        await s3_client.put_object(
            Bucket=s3_bucket,
            Key=metadata.s3_object_key,
            Metadata=s3_object_metadata,
            ContentType=content_type,
            Body=content,
        )
        logger.info("Object created: %s", metadata.s3_object_key)

    metadata.save()
    logger.info("Metadata saved: %s", metadata.id)

    async with aiomqtt.Client(request.app.settings.mqtt_broker) as mqtt_client:
        await mqtt_client.publish(
            request.app.settings.mqtt_topic,
            json.dumps(get_new_aggregate_event_message(metadata, request.app.settings)),
        )

    return Response(status_code=status.HTTP_201_CREATED, headers={"Location": location})


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
        async with get_s3_client(request.app.settings) as s3_client:
            s3_obj = await s3_client.get_object(
                Bucket=metadata.s3_bucket, Key=metadata.s3_object_key
            )

        metadata_location = f"/api/v1/aggregates/{aggregate_id}"

        return StreamingResponse(
            content=s3_obj["Body"],
            media_type=metadata.content_type,
            headers={
                "Link": f'{metadata_location}; rel="about"',
                # "Content-Length": str(metadata.content_length),
            },
        )

    raise HTTPException(status.HTTP_404_NOT_FOUND)
