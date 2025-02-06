import argparse
import asyncio
import logging
from contextlib import asynccontextmanager

import aiobotocore.session
import aiomqtt
import boto3
import mongoengine
import nats
import nats.errors
import uvicorn
from aiomqtt.exceptions import MqttError
from fastapi import FastAPI
from opentelemetry import trace
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

import aggrec.aggregates
import aggrec.extras
from dnstapir.key_cache import key_cache_from_settings
from dnstapir.key_resolver import key_resolver_from_client_database
from dnstapir.logging import setup_logging
from dnstapir.opentelemetry import configure_opentelemetry
from dnstapir.starlette import LoggingMiddleware

from . import OPENAPI_METADATA, __verbose_version__
from .settings import MqttSettings, NatsSettings, Settings

logger = logging.getLogger(__name__)

tracer = trace.get_tracer("aggrec.tracer")


class AggrecServer(FastAPI):
    def __init__(self, settings: Settings):
        self.logger = logging.getLogger(__name__).getChild(self.__class__.__name__)
        self.settings = settings
        super().__init__(**OPENAPI_METADATA, lifespan=self.lifespan)

        self.add_middleware(ProxyHeadersMiddleware)
        self.add_middleware(LoggingMiddleware)

        self.include_router(aggrec.aggregates.router)
        self.include_router(aggrec.extras.router)

        if self.settings.otlp:
            configure_opentelemetry(
                service_name="aggrec",
                settings=self.settings.otlp,
                fastapi_app=self,
            )
        else:
            self.logger.info("Configured without OpenTelemetry")
        key_cache = key_cache_from_settings(self.settings.key_cache) if self.settings.key_cache else None
        self.key_resolver = key_resolver_from_client_database(
            client_database=self.settings.clients_database, key_cache=key_cache
        )

        self.mqtt_new_aggregate_messages: asyncio.Queue[str] | None = (
            asyncio.Queue(maxsize=self.settings.mqtt.queue_size) if self.settings.mqtt else None
        )
        self.nats_new_aggregate_messages: asyncio.Queue[str] | None = (
            asyncio.Queue(maxsize=self.settings.nats.queue_size) if self.settings.nats else None
        )

    def connect_mongodb(self):
        if mongodb_host := str(self.settings.mongodb.server):
            params = {"host": mongodb_host}
            if "host" in params and params["host"].startswith("mongomock://"):
                import mongomock

                params["host"] = params["host"].replace("mongomock://", "mongodb://")
                params["mongo_client_class"] = mongomock.MongoClient
            self.logger.info("Connecting to MongoDB %s", params)
            mongoengine.connect(**params, tz_aware=True)
            self.logger.info("MongoDB connected")

    def get_mqtt_client(self, settings: MqttSettings) -> aiomqtt.Client:
        assert settings is not None
        self.logger.debug("Connecting to MQTT broker %s", settings.broker)
        client = aiomqtt.Client(
            hostname=settings.broker.host,
            port=settings.broker.port,
            username=settings.broker.username,
            password=settings.broker.password,
        )
        self.logger.debug("Created MQTT client %s", client)
        return client

    async def get_nats_client(self, settings: NatsSettings) -> nats.NATS:
        assert settings is not None
        servers = [str(server) for server in settings.servers]
        self.logger.debug("Connecting to NATS servers %s", servers)
        client = await nats.connect(
            servers=servers,
            name=settings.name,
            user=settings.user,
            password=settings.password,
        )
        self.logger.debug("Created NATS client %s", client)
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

    async def mqtt_publisher(self):
        """Task for publishing enqueued MQTT messages"""
        _logger = self.logger.getChild("mqtt_publisher")
        _logger.debug("Starting MQTT publish task")
        assert self.settings.mqtt is not None
        while True:
            try:
                async with self.get_mqtt_client(self.settings.mqtt) as mqtt_client:
                    _logger.info("Connected to MQTT broker")
                    while True:
                        _logger.debug("Waiting for MQTT messages")
                        message = await self.mqtt_new_aggregate_messages.get()
                        _logger.debug(
                            "Publishing new aggregate message on MQTT topic %s",
                            self.settings.mqtt.topic,
                        )
                        with tracer.start_as_current_span("mqtt.publish"):
                            await mqtt_client.publish(
                                topic=self.settings.mqtt.topic,
                                payload=message.encode(),
                            )
            except MqttError as exc:
                _logger.error("MQTT error: %s", str(exc))
            except asyncio.exceptions.CancelledError:
                _logger.debug("MQTT publish task cancelled")
                return
            _logger.info(
                "Reconnecting to MQTT broker in %d seconds",
                self.settings.mqtt.reconnect_interval,
            )
            await asyncio.sleep(self.settings.mqtt.reconnect_interval)

    async def nats_publisher(self):
        """Task for publishing enqueued NATS messages"""
        _logger = self.logger.getChild("nats_publisher")
        _logger.debug("Starting NATS publish task")
        assert self.settings.nats is not None
        while True:
            try:
                nats_client = await self.get_nats_client(self.settings.nats)
                _logger.info("Connected to NATS servers")
                while True:
                    _logger.debug("Waiting for NATS messages")
                    message = await self.nats_new_aggregate_messages.get()
                    _logger.debug(
                        "Publishing new aggregate message on NATS topic %s",
                        self.settings.nats.subject,
                    )
                    with tracer.start_as_current_span("nats.publish"):
                        await nats_client.publish(
                            subject=self.settings.nats.subject,
                            payload=message.encode(),
                        )
            except nats.errors.ConnectionClosedError as exc:
                _logger.error("NATS connection closed: %s", str(exc))
            except asyncio.exceptions.CancelledError:
                _logger.debug("NATS publish task cancelled")
                return
            except Exception as exc:
                _logger.error("NATS connection error: %s", str(exc))
            finally:
                if not nats_client.is_closed:
                    await nats_client.close()
            _logger.info(
                "Reconnecting to NATS server in %d seconds",
                self.settings.nats.reconnect_interval,
            )
            await asyncio.sleep(self.settings.nats.reconnect_interval)

    @staticmethod
    @asynccontextmanager
    async def lifespan(app: "AggrecServer"):
        app.logger.debug("Lifespan startup")
        app.connect_mongodb()
        tasks = []
        if app.settings.mqtt:
            tasks.append(asyncio.create_task(app.mqtt_publisher()))
        if app.settings.nats:
            tasks.append(asyncio.create_task(app.nats_publisher()))
        logger.debug("Background tasks started")
        yield
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.debug("All background tasks cancelled")
        app.logger.debug("Lifespan ended")


def main() -> None:
    """Main function"""

    parser = argparse.ArgumentParser(description="Aggregate Receiver")

    parser.add_argument("--host", help="Host address to bind to", default="0.0.0.0")
    parser.add_argument("--port", help="Port to listen on", type=int, default=8080)
    parser.add_argument("--log-json", action="store_true", help="Enable JSON logging")
    parser.add_argument("--debug", action="store_true", help="Enable debugging")
    parser.add_argument("--version", action="store_true", help="Show version")

    args = parser.parse_args()

    if args.version:
        print(f"Aggregate Receiver version {__verbose_version__}")
        return

    setup_logging(json_logs=args.log_json, log_level="DEBUG" if args.debug else "INFO")

    logger.info("Starting Aggregate Receiver version %s", __verbose_version__)
    app = AggrecServer(settings=Settings())

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_config=None,
        log_level=None,
        headers=[("server", f"dnstapir-aggrec/{__verbose_version__}")],
    )


if __name__ == "__main__":
    main()
