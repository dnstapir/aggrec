from typing import Annotated, Tuple, Type

from pydantic import AnyHttpUrl, BaseModel, DirectoryPath, Field, UrlConstraints
from pydantic_core import Url
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

MqttUrl = Annotated[
    Url,
    UrlConstraints(
        allowed_schemes=["mqtt", "mqtts"], default_port=1883, host_required=True
    ),
]

MongodbUrl = Annotated[
    Url,
    UrlConstraints(allowed_schemes=["mongodb"], default_port=27017, host_required=True),
]


class MqttSettings(BaseModel):
    broker: MqttUrl = Field(default="mqtt://localhost")
    username: str | None = None
    password: str | None = None
    topic: str = Field(default="aggregates")
    reconnect_interval: int = Field(default=5)


class MongoDB(BaseModel):
    server: MongodbUrl | None = Field(default="mongodb://localhost/aggregates")


class S3(BaseModel):
    endpoint_url: AnyHttpUrl = Field(default="http://localhost:9000")
    access_key_id: str | None = None
    secret_access_key: str | None = None
    bucket: str
    create_bucket: bool = False


class Settings(BaseSettings):
    metadata_base_url: AnyHttpUrl = Field(default="http://127.0.0.1")
    clients_database: DirectoryPath = Field(default="clients")
    s3: S3 = Field()
    mqtt: MqttSettings = Field(default=MqttSettings())
    mongodb: MongoDB = Field()

    model_config = SettingsConfigDict(toml_file="aggrec.toml")

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        return (TomlConfigSettingsSource(settings_cls),)
