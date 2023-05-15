import json
import logging
from typing import Dict
from urllib.parse import urljoin

import boto3
import paho.mqtt.client as mqtt
from bson.objectid import ObjectId
from flask import Blueprint, Response, current_app, g, request, send_file
from werkzeug.exceptions import BadRequest, NotFound

from .db_models import AggregateMetadata
from .helpers import RequestVerifier

logger = logging.getLogger(__name__)

bp = Blueprint("aggregates", __name__)


METADATA_HTTP_HEADERS = [
    "Content-Length",
    "Content-Type",
    "Content-Digest",
    "Signature",
    "Signature-Input",
]

ALLOWED_AGGREGATE_TYPES = ["histogram", "vector"]

ALLOWED_CONTENT_TYPES = ["application/vnd.apache.parquet", "application/binary"]


def get_http_request_verifier() -> RequestVerifier:
    if "http_request_verifier" not in g:
        g.http_request_verifier = RequestVerifier()
        logging.warning("HTTP request verifier created")
    return g.http_request_verifier


def get_s3_client():
    if "s3_client" not in g:
        g.s3_client = boto3.client(
            "s3",
            endpoint_url=current_app.config["S3_ENDPOINT_URL"],
            aws_access_key_id=current_app.config["S3_ACCESS_KEY_ID"],
            aws_secret_access_key=current_app.config["S3_SECRET_ACCESS_KEY"],
            aws_session_token=None,
            config=boto3.session.Config(signature_version="s3v4"),
        )
        logging.warning("S3 client created")
    return g.s3_client


def get_mqtt_client():
    if "mqtt_client" not in g:
        client = mqtt.Client()
        client.connect(current_app.config["MQTT_BROKER"])
        g.mqtt_client = client
        logging.warning("MQTT client created")
    return g.mqtt_client


def get_http_headers() -> Dict[str, str]:
    """Get dictionary of relevant metadata HTTP headers"""
    res = {}
    for header in METADATA_HTTP_HEADERS:
        if value := request.headers.get(header):
            res[header] = value
    return res


def get_new_aggregate_event_message(metadata: AggregateMetadata) -> dict:
    """Get new aggregate event message"""
    return {
        "type": "new_aggregate",
        "aggregate_id": str(metadata.id),
        "aggregate_type": metadata.aggregate_type.value,
        "created": metadata.id.generation_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "creator": str(metadata.creator),
        "metadata_location": urljoin(
            current_app.config["METADATA_BASE_URL"],
            f"/aggregates/{metadata.id}",
        ),
        "payload_location": urljoin(
            current_app.config["METADATA_BASE_URL"],
            f"/aggregates/{metadata.id}/payload",
        ),
    }


@bp.route("/aggregate/<aggregate_type>", methods=["POST"])
def create_aggregate(aggregate_type: str):
    if aggregate_type not in ALLOWED_AGGREGATE_TYPES:
        raise BadRequest(description="Aggregate type not supported")

    if request.content_type not in ALLOWED_CONTENT_TYPES:
        raise BadRequest(description="Content-Type not supported")

    res = get_http_request_verifier().verify(request)
    mqtt_client = get_mqtt_client()

    creator = res.get("keyid")

    aggregate_id = ObjectId()
    location = f"/aggregates/{aggregate_id}"

    s3_bucket = current_app.config["S3_BUCKET"]
    s3_object_key = f"type={aggregate_type}/creator={creator}/{aggregate_id}"

    s3 = get_s3_client()
    s3.put_object(Bucket=s3_bucket, Key=s3_object_key, Body=request.data)

    metadata = AggregateMetadata(
        id=aggregate_id,
        aggregate_type=aggregate_type,
        creator=creator,
        http_headers=get_http_headers(),
        content_type=request.content_type,
        content_length=request.content_length,
        s3_bucket=s3_bucket,
        s3_object_key=s3_object_key,
    )
    metadata.save()

    mqtt_client.publish(
        current_app.config["MQTT_TOPIC"],
        json.dumps(get_new_aggregate_event_message(metadata)),
    )

    return Response(status=201, headers={"Location": location})


@bp.route("/aggregates/<aggregate_id>", methods=["GET"])
def get_aggregate_metadata(aggregate_id: str):
    if metadata := AggregateMetadata.objects(id=ObjectId(aggregate_id)).first():
        return {
            "aggregate_id": str(metadata.id),
            "aggregate_type": metadata.aggregate_type.value,
            "created": metadata.id.generation_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creator": str(metadata.creator),
            "headers": metadata.http_headers,
            "content_type": metadata.content_type,
            "content_length": metadata.content_length,
            "payload": urljoin(
                current_app.config["METADATA_BASE_URL"],
                f"/aggregates/{aggregate_id}/payload",
            ),
        }

    raise NotFound


@bp.route("/aggregates/<aggregate_id>/payload", methods=["GET"])
def get_aggregate_payload(aggregate_id: str):
    if metadata := AggregateMetadata.objects(id=ObjectId(aggregate_id)).first():
        s3 = get_s3_client()
        s3_obj = s3.get_object(Bucket=metadata.s3_bucket, Key=metadata.s3_object_key)
        metadata_location = f"/aggregates/{aggregate_id}"
        response = send_file(s3_obj["Body"], mimetype=metadata.content_type)
        response.headers.update({"Link": f'{metadata_location}; rel="about"'})
        return response
    raise NotFound
