import json
import logging
from enum import Enum
from functools import lru_cache
from typing import Annotated, Dict
from urllib.parse import urljoin

import aiobotocore.session
import aiomqtt
import boto3
import bson
from bson.objectid import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from .db_models import AggregateMetadata
from .helpers import (
    InvalidContentDigest,
    InvalidSignature,
    RequestVerifier,
    rfc_3339_datetime_now,
)
from .settings import Settings

logger = logging.getLogger(__name__)


METADATA_HTTP_HEADERS = [
    "Content-Length",
    "Content-Type",
    "Content-Digest",
    "Content-Encoding",
    "Signature",
    "Signature-Input",
]

ALLOWED_AGGREGATE_TYPES = ["histogram", "vector"]

ALLOWED_CONTENT_TYPES = ["application/vnd.apache.parquet", "application/binary"]

router = APIRouter()


class AggregateType(str, Enum):
    histogram = "histogram"
    vector = "vector"


class AggregateMetadataResponse(BaseModel):
    aggregate_id: str
    aggregate_type: AggregateType
    created: str
    creator: str
    headers: dict
    content_type: str
    content_length: int
    content_location: str
    s3_bucket: str
    s3_object_key: str

    @classmethod
    def from_db_model(cls, metadata: AggregateMetadata, settings: Settings):
        aggregate_id = str(metadata.id)
        return cls(
            aggregate_id=aggregate_id,
            aggregate_type=metadata.aggregate_type.value,
            created=metadata.id.generation_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
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
    }


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
    s3_object_key = f"type={aggregate_type}/creator={creator}/{aggregate_id}"

    if settings.s3_bucket_create:
        try:
            await s3_client.create_bucket(Bucket=s3_bucket)
        except Exception:
            pass

    content = await request.body()
    content_length = len(content)

    await s3_client.put_object(Bucket=s3_bucket, Key=s3_object_key, Body=content)

    metadata = AggregateMetadata(
        id=aggregate_id,
        aggregate_type=aggregate_type,
        creator=creator,
        http_headers=get_http_headers(request),
        content_type=content_type,
        content_length=content_length,
        s3_bucket=s3_bucket,
        s3_object_key=s3_object_key,
    )
    metadata.save()

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


@router.get("/api/v1/aggregates/{aggregate_id}/payload")
async def get_aggregate_payload(
    aggregate_id: str,
    settings: Annotated[Settings, Depends(get_settings)],
    s3_client: Annotated[aiobotocore.client.AioBaseClient, Depends(s3_client)],
):
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
