from datetime import datetime
from enum import Enum
from urllib.parse import urljoin

from pydantic import BaseModel, Field

from .db_models import AggregateMetadata
from .settings import Settings


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


class HealthcheckResult(BaseModel):
    status: str = Field(title="Status")
    aggregates_count: int = Field(title="Number of aggregates in database")
