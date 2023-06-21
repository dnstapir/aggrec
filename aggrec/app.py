import json
import logging
import os
from typing import Optional

import mongoengine
import toml
from flask import Flask

from .aggregates import bp as aggregate_bp


def create_app(config_filename: Optional[str] = None):
    app = Flask(__name__)

    config_filename = config_filename or os.environ.get("AGGREC_CONFIG")

    if config_filename:
        logging.info("Reading configuration from %s", config_filename)
        app.config.from_file(config_filename, load=toml.load)

    if mongodb_host := app.config.get("MONGODB_HOST"):
        params = {"host": mongodb_host}
        if "host" in params and params["host"].startswith("mongomock://"):
            import mongomock

            params["host"] = params["host"].replace("mongomock://", "mongodb://")
            params["mongo_client_class"] = mongomock.MongoClient
        logging.info("Mongoengine connect %s", json.dumps(params))
        mongoengine.connect(**params, tz_aware=True)

    app.register_blueprint(aggregate_bp)

    return app
