import tomllib
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    metadata_base_url: str
    clients_database: str
    s3_endpoint_url: str
    s3_access_key_id: Optional[str]
    s3_secret_access_key: Optional[str]
    s3_bucket: str
    s3_bucket_create: bool
    mongodb_host: Optional[str]
    mqtt_broker: Optional[str]
    mqtt_topic: str

    @classmethod
    def from_file(cls, filename: str):
        with open(filename, "rb") as fp:
            data = tomllib.load(fp)

        return cls(
            metadata_base_url=data.get("METADATA_BASE_URL", "http://127.0.0.1"),
            clients_database=data.get("CLIENTS_DATABASE", "clients"),
            s3_endpoint_url=data.get("S3_ENDPOINT_URL", "http://localhost:9000"),
            s3_access_key_id=data.get("S3_ACCESS_KEY_ID"),
            s3_secret_access_key=data.get("S3_SECRET_ACCESS_KEY"),
            s3_bucket=data.get("S3_BUCKET", "aggregates"),
            s3_bucket_create=data.get("S3_BUCKET_CREATE", False),
            mongodb_host=data.get("MONGODB_HOST", "mongodb://localhost/aggregates"),
            mqtt_broker=data.get("MQTT_BROKER"),
            mqtt_topic=data.get("MQTT_TOPIC", "aggregates"),
        )
