import json
import logging
from datetime import datetime, timezone
from enum import Enum
from functools import lru_cache
from typing import Annotated, Dict
from urllib.parse import urljoin

import aiobotocore.session
import aiomqtt
import boto3
import bson
import pendulum
from bson.objectid import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .db_models import AggregateMetadata
from .helpers import RequestVerifier, pendulum_as_datetime, rfc_3339_datetime_now
from .settings import Settings

logger = logging.getLogger(__name__)


METADATA_HTTP_HEADERS = [
    "Content-Length",
    "Content-Type",
    "Content-Digest",
    "Content-Encoding",
    "Signature",
    "Signature-Input",
    "Aggregate-Interval",
]

ALLOWED_AGGREGATE_TYPES = ["histogram", "vector"]

ALLOWED_CONTENT_TYPES = ["application/vnd.apache.parquet", "application/binary"]

router = APIRouter()


class AggregateType(str, Enum):
    histogram = "histogram"
    vector = "vector"


class AggregateMetadataResponse(BaseModel):
    aggregate_id: str = Field(title="Aggregate identifier")
    aggregate_type: AggregateType = Field(title="Aggregate type")
    created: datetime = Field(title="Aggregate creation timestamp")
    creator: str = Field(title="Aggregate creator")
    headers: dict = Field(title="Dictionary of relevant HTTP headers")
    content_type: str = Field(title="Content MIME type")
    content_length: int = Field(title="Content length")
    content_location: str = Field(title="Content local (URL)")
    s3_bucket: str = Field(title="S3 Bucket Name")
    s3_object_key: str = Field(title="S3 Object Key")
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


@lru_cache
def get_settings():
    return Settings()


def http_request_verifier(settings: Annotated[Settings, Depends(get_settings)]):
    return RequestVerifier(client_database=settings.clients_database)


async def s3_client(settings: Annotated[Settings, Depends(get_settings)]):
    logger.debug("Returning settings")
    session = aiobotocore.session.AioSession()
    async with session.create_client(
        "s3",
        endpoint_url=settings.s3_endpoint_url,
        aws_access_key_id=settings.s3_access_key_id,
        aws_secret_access_key=settings.s3_secret_access_key,
        aws_session_token=None,
        config=boto3.session.Config(signature_version="s3v4"),
    ) as client:
        yield client


async def mqtt_client(settings: Annotated[Settings, Depends(get_settings)]):
    async with aiomqtt.Client(settings.mqtt_broker) as client:
        yield client


def get_http_headers(request: Request) -> Dict[str, str]:
    """Get dictionary of relevant metadata HTTP headers"""
    res = {}
    for header in METADATA_HTTP_HEADERS:
        if value := request.headers.get(header):
            res[header] = value
    return res


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
                "interval_start": metadata.aggregate_interval_start.astimezone(
                    tz=timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "interval_duration": metadata.aggregate_interval_duration,
            }
            if metadata.aggregate_interval_start
            and metadata.aggregate_interval_duration
            else {}
        ),
    }


def get_s3_object_key(metadata: AggregateMetadata) -> str:
    """Get S3 object key from metadata"""
    dt = metadata.aggregate_interval_start or metadata.id.generation_time
    fields_dict = {
        "type": metadata.aggregate_type.name.lower(),
        "year": f"{dt.year:04}",
        "month": f"{dt.month:02}",
        "day": f"{dt.day:02}",
        "hour": f"{dt.hour:02}",
        "minute": f"{dt.minute:02}",
        "creator": metadata.creator,
        "id": metadata.id,
    }
    fields_list = [f"{k}={v}" for k, v in fields_dict.items() if v is not None]
    return "/".join(fields_list)


@router.post("/api/v1/aggregate/{aggregate_type}")
async def create_aggregate(
    aggregate_type: AggregateType,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    s3_client: Annotated[aiobotocore.client.AioBaseClient, Depends(s3_client)],
    mqtt_client: Annotated[aiomqtt.Client, Depends(mqtt_client)],
    http_request_verifier: Annotated[RequestVerifier, Depends(http_request_verifier)],
):
    if aggregate_type not in ALLOWED_AGGREGATE_TYPES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Aggregate type not supported")

    content_type = request.headers.get("content-type", None)

    if content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Content-Type not supported")

    res = await http_request_verifier.verify(request)

    creator = res.get("keyid")
    logger.info("Create aggregate request by keyid=%s", creator)

    aggregate_id = ObjectId()
    location = f"/api/v1/aggregates/{aggregate_id}"

    s3_bucket = settings.s3_bucket

    if aggregate_interval := request.headers.get("Aggregate-Interval"):
        period = pendulum.parse(aggregate_interval)
        if not isinstance(period, pendulum.Period):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "Invalid Aggregate-Interval"
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
        http_headers=get_http_headers(request),
        content_type=content_type,
        s3_bucket=s3_bucket,
    )

    content = await request.body()

    metadata.content_length = len(content)
    metadata.s3_object_key = get_s3_object_key(metadata)

    if settings.s3_bucket_create:
        try:
            await s3_client.create_bucket(Bucket=s3_bucket)
        except Exception:
            pass

    await s3_client.put_object(
        Bucket=s3_bucket, Key=metadata.s3_object_key, Body=content
    )
    logger.info("Object created: %s", metadata.s3_object_key)

    metadata.save()
    logger.info("Metadata saved: %s", metadata.id)

    await mqtt_client.publish(
        settings.mqtt_topic,
        json.dumps(get_new_aggregate_event_message(metadata, settings)),
    )

    return Response(status_code=status.HTTP_201_CREATED, headers={"Location": location})


@router.get("/api/v1/aggregates/{aggregate_id}")
def get_aggregate_metadata(
    aggregate_id: str, settings: Annotated[Settings, Depends(get_settings)]
) -> AggregateMetadataResponse:
    try:
        aggregate_object_id = ObjectId(aggregate_id)
    except bson.errors.InvalidId:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    if metadata := AggregateMetadata.objects(id=aggregate_object_id).first():
        return AggregateMetadataResponse.from_db_model(metadata, settings)

    raise HTTPException(status.HTTP_404_NOT_FOUND)


@router.get(
    "/api/v1/aggregates/{aggregate_id}/payload",
    responses={
        200: {
            "description": "Aggregate payload",
            "content": {
                "application/vnd.apache.parquet": {},
                "application/binary": {},
            },
        }
    },
)
async def get_aggregate_payload(
    aggregate_id: str,
    settings: Annotated[Settings, Depends(get_settings)],
    s3_client: Annotated[aiobotocore.client.AioBaseClient, Depends(s3_client)],
) -> bytes:
    try:
        aggregate_object_id = ObjectId(aggregate_id)
    except bson.errors.InvalidId:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    if metadata := AggregateMetadata.objects(id=aggregate_object_id).first():
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
