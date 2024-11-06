import argparse
import logging

import aiobotocore.session
import aiomqtt
import boto3
import mongoengine
import uvicorn
from fastapi import FastAPI
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

import aggrec.aggregates
import aggrec.extras
from dnstapir.key_cache import key_cache_from_settings
from dnstapir.key_resolver import key_resolver_from_client_database
from dnstapir.logging import configure_json_logging
from dnstapir.telemetry import configure_opentelemetry

from . import OPENAPI_METADATA, __verbose_version__
from .settings import Settings

logger = logging.getLogger(__name__)


class AggrecServer(FastAPI):
    def __init__(self, settings: Settings):
        self.logger = logging.getLogger(__name__).getChild(self.__class__.__name__)
        self.settings = settings
        super().__init__(**OPENAPI_METADATA)
        self.add_middleware(ProxyHeadersMiddleware)
        self.include_router(aggrec.aggregates.router)
        self.include_router(aggrec.extras.router)
        configure_opentelemetry(
            self,
            service_name="aggrec",
            spans_endpoint=str(settings.otlp.spans_endpoint),
            metrics_endpoint=str(settings.otlp.metrics_endpoint),
            insecure=settings.otlp.insecure,
        )
        key_cache = key_cache_from_settings(self.settings.key_cache) if self.settings.key_cache else None
        self.key_resolver = key_resolver_from_client_database(
            client_database=str(self.settings.clients_database), key_cache=key_cache
        )

    @staticmethod
    def connect_mongodb(settings: Settings):
        if mongodb_host := str(settings.mongodb.server):
            params = {"host": mongodb_host}
            if "host" in params and params["host"].startswith("mongomock://"):
                import mongomock

                params["host"] = params["host"].replace("mongomock://", "mongodb://")
                params["mongo_client_class"] = mongomock.MongoClient
            logger.info("Mongoengine connect %s", params)
            mongoengine.connect(**params, tz_aware=True)

    def get_mqtt_client(self) -> aiomqtt.Client:
        client = aiomqtt.Client(
            hostname=self.settings.mqtt.broker.host,
            port=self.settings.mqtt.broker.port,
            username=self.settings.mqtt.broker.username,
            password=self.settings.mqtt.broker.password,
        )
        self.logger.debug("Created MQTT client %s", client)
        return client

    def get_s3_client(self) -> aiobotocore.session.ClientCreatorContext:
        session = aiobotocore.session.AioSession()
        client = session.create_client(
            service_name="s3",
            endpoint_url=str(self.settings.s3.endpoint_url),
            aws_access_key_id=self.settings.s3.access_key_id,
            aws_secret_access_key=self.settings.s3.secret_access_key,
            aws_session_token=None,
            config=boto3.session.Config(signature_version="s3v4"),
        )
        self.logger.debug("Created S3 client %s", client)
        return client

    @classmethod
    def factory(cls):
        logger.info("Starting Aggregate Receiver version %s", __verbose_version__)
        app = cls(settings=Settings())
        app.connect_mongodb(app.settings)
        return app


def main() -> None:
    """Main function"""

    parser = argparse.ArgumentParser(description="Aggregate Receiver")

    parser.add_argument("--host", help="Host address to bind to", default="0.0.0.0")
    parser.add_argument("--port", help="Port to listen on", type=int, default=8080)
    parser.add_argument("--debug", action="store_true", help="Enable debugging")
    parser.add_argument("--version", action="store_true", help="Show version")

    args = parser.parse_args()

    if args.version:
        print(f"Aggregate Receiver version {__verbose_version__}")
        return

    logging_config = configure_json_logging()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
        log_level = "debug"
    else:
        logging.basicConfig(level=logging.INFO)
        log_level = "info"

    app = AggrecServer.factory()

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_config=logging_config,
        log_level=log_level,
        headers=[("server", f"dnstapir-aggrec/{__verbose_version__}")],
    )


if __name__ == "__main__":
    main()
