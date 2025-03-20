from datetime import datetime
from typing import Annotated

from pydantic import AnyHttpUrl, BaseModel, Field, UrlConstraints
from pydantic.networks import IPv4Address, IPvAnyAddress, IPvAnyNetwork
from pydantic_core import Url
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict, TomlConfigSettingsSource

from dnstapir.key_cache import KeyCacheSettings
from dnstapir.opentelemetry import OtlpSettings

MqttUrl = Annotated[
    Url,
    UrlConstraints(allowed_schemes=["mqtt", "mqtts"], default_port=1883, host_required=True),
]

NatsUrl = Annotated[
    Url,
    UrlConstraints(allowed_schemes=["nats", "tls"], default_port=4222, host_required=True),
]

MongodbUrl = Annotated[
    Url,
    UrlConstraints(allowed_schemes=["mongodb"], default_port=27017, host_required=True),
]


class HttpSettings(BaseModel):
    trusted_hosts: list[IPvAnyAddress | IPvAnyNetwork] = Field(default=[IPv4Address("127.0.0.1")])


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
        return datetime.now(tz=datetime.UTC).strftime(self.bucket)


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

    model_config = SettingsConfigDict(toml_file="aggrec.toml")

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (TomlConfigSettingsSource(settings_cls),)
