import os
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network, IPv6Network
from typing import Annotated

from pydantic import AnyHttpUrl, BaseModel, Field, UrlConstraints
from pydantic.networks import IPvAnyAddress, IPvAnyNetwork
from pydantic_core import Url
from pydantic_settings import BaseSettings, EnvSettingsSource, PydanticBaseSettingsSource, TomlConfigSettingsSource

from dnstapir.key_cache import KeyCacheSettings
from dnstapir.opentelemetry import OtlpSettings

ENV_PREFIX = "AGGREC_"

MqttUrl = Annotated[
    Url,
    UrlConstraints(allowed_schemes=["mqtt", "mqtts"], host_required=True),
]

NatsUrl = Annotated[
    Url,
    UrlConstraints(allowed_schemes=["nats", "tls"], default_port=4222, host_required=True),
]

MongodbUrl = Annotated[
    Url,
    UrlConstraints(allowed_schemes=["mongodb", "mongodb+srv", "mongomock"], host_required=True),
]


class HttpSettings(BaseModel):
    trusted_hosts: list[IPvAnyAddress | IPvAnyNetwork] = Field(
        default=[
            IPv4Address("127.0.0.1"),
        ]
    )
    healthcheck_hosts: list[IPvAnyNetwork] = Field(
        default=[
            IPv4Network("127.0.0.1/32"),
            IPv4Network("10.0.0.0/8"),
            IPv4Network("172.16.0.0/12"),
            IPv4Network("192.168.0.0/16"),
            IPv6Network("fe80::/10"),
        ]
    )


class MqttSettings(BaseModel):
    broker: MqttUrl = Field(default="mqtt://localhost")
    username: str | None = None
    password: str | None = None
    topic: str = Field(default="aggregates")
    reconnect_interval: int = Field(default=5)
    queue_size: int = Field(default=1024)


class NatsSettings(BaseModel):
    servers: list[NatsUrl] = Field(default=["nats://localhost:4222"])
    name: str = Field(default="aggrec")
    user: str | None = None
    password: str | None = None
    subject: str = Field(default="aggregates")
    reconnect_interval: int = Field(default=5)
    queue_size: int = Field(default=1024)


class MongoDB(BaseModel):
    server: MongodbUrl | None = Field(default="mongodb://localhost/aggregates")
    timeout: int = Field(default=5)


class S3(BaseModel):
    endpoint_url: AnyHttpUrl = Field(default="http://localhost:9000")
    access_key_id: str | None = None
    secret_access_key: str | None = None
    bucket: str = Field(default="aggrec")
    create_bucket: bool = False

    def get_bucket_name(self) -> str:
        return datetime.now(tz=UTC).strftime(self.bucket)


class Settings(BaseSettings):
    metadata_base_url: AnyHttpUrl = Field(default="http://127.0.0.1")
    clients_database: str = Field(default="clients")
    s3: S3 = Field(default=S3())
    mqtt: MqttSettings | None = None
    nats: NatsSettings | None = None
    mongodb: MongoDB = Field(default=MongoDB())
    otlp: OtlpSettings | None = None
    key_cache: KeyCacheSettings | None = None

    http: HttpSettings = Field(default=HttpSettings())

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            EnvSettingsSource(
                settings_cls,
                env_prefix=ENV_PREFIX,
                env_nested_delimiter="__",
                env_ignore_empty=True,
                case_sensitive=False,
            ),
            TomlConfigSettingsSource(
                settings_cls,
                toml_file=os.environ.get("AGGREC_CONFIG", "aggrec.toml"),
            ),
        )
