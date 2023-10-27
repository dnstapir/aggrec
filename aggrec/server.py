import argparse
import logging
import os
from functools import lru_cache
from typing import Optional

import mongoengine
import uvicorn
from fastapi import FastAPI

import aggrec.aggregates
from aggrec.settings import Settings

logger = logging.getLogger(__name__)

app = None


def configure_app(config_filename: Optional[str]):
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


def create_app(config_filename: Optional[str]):
    app = FastAPI()

    settings = configure_app(config_filename)

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

    parser.add_argument(
        "--config", dest="config", metavar="filename", help="Configuration file"
    )
    parser.add_argument(
        "--host", dest="host", help="Host address to bind to", default="0.0.0.0"
    )
    parser.add_argument(
        "--port", dest="port", type=int, help="Port to listen on", default=8080
    )
    parser.add_argument(
        "--debug", dest="debug", action="store_true", help="Enable debugging"
    )

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
        log_level = "debug"
    else:
        logging.basicConfig(level=logging.INFO)
        log_level = "info"

    app = create_app(args.config)

    uvicorn.run(app, host=args.host, port=args.port, log_level=log_level)


if __name__ == "__main__":
    main()
