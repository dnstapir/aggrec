import argparse
import logging
import os
from functools import lru_cache
from typing import Optional

import mongoengine
import uvicorn
from fastapi import FastAPI

import aggrec.aggregates
from aggrec import __verbose_version__
from aggrec.logging import JsonFormatter  # noqa
from aggrec.settings import Settings

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


def create_settings(config_filename: Optional[str]):
    config_filename = config_filename or os.environ.get("AGGREC_CONFIG")
    if config_filename:
        logger.info("Reading configuration from %s", config_filename)
        return Settings.from_file(config_filename)
    else:
        return Settings()


def connect_mongodb(settings: Settings):
    if mongodb_host := settings.mongodb_host:
        params = {"host": mongodb_host}
        if "host" in params and params["host"].startswith("mongomock://"):
            import mongomock

            params["host"] = params["host"].replace("mongomock://", "mongodb://")
            params["mongo_client_class"] = mongomock.MongoClient
        logger.info("Mongoengine connect %s", params)
        mongoengine.connect(**params, tz_aware=True)


def app_factory(config_filename: Optional[str]):
    app = FastAPI()
    settings = create_settings(config_filename)

    @lru_cache
    def get_settings_override():
        logger.debug("Returning settings")
        return settings

    app.include_router(aggrec.aggregates.router)
    app.dependency_overrides[aggrec.aggregates.get_settings] = get_settings_override

    connect_mongodb(settings)

    return app


def main() -> None:
    """Main function"""

    parser = argparse.ArgumentParser(description="Aggregate Receiver")

    parser.add_argument("--config", metavar="filename", help="Configuration file")
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

    app = app_factory(args.config)

    logger.info("Starting Aggregate Receiver version %s", __verbose_version__)

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
