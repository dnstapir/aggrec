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

from . import OPENAPI_METADATA, __verbose_version__
from .logging import JsonFormatter  # noqa
from .settings import Settings
from .telemetry import configure_opentelemetry

logger = logging.getLogger(__name__)

LOGGING_RECORD_CUSTOM_FORMAT = {
    "time": "asctime",
    # "Created": "created",
    # "RelativeCreated": "relativeCreated",
    "name": "name",
    # "Levelno": "levelno",
    "levelname": "levelname",
    "process": "process",
    "thread": "thread",
    # "threadName": "threadName",
    # "Pathname": "pathname",
    # "Filename": "filename",
    # "Module": "module",
    # "Lineno": "lineno",
    # "FuncName": "funcName",
    "message": "message",
}

LOGGING_CONFIG_JSON = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "class": "aggrec.logging.JsonFormatter",
            "format": LOGGING_RECORD_CUSTOM_FORMAT,
        },
    },
    "handlers": {
        "json": {"class": "logging.StreamHandler", "formatter": "json"},
    },
    "root": {"handlers": ["json"], "level": "DEBUG"},
}


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

    logging_config = LOGGING_CONFIG_JSON
    logging.config.dictConfig(logging_config)

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
