# DNS TAPIR Aggregate Receiver

This repository contains the DNS TAPIR Aggregate Receiver, a server component use for submitting and retrieving TAPIR aggregates.

Submitted aggregates are stored in a S3 compatible object store with its metadata stored in MongoDB. New aggregates are announced via MQTT.

Client are assumed to be authenticated using mTLS and all submitted data must be signed using [HTTP Message Signatures](https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures). Public keys for allowed signers are stored in PEM format in the `CLIENTS_DATABASE` directory as `{key_id}.pem`.


## Configuration

    METADATA_BASE_URL = "http://127.0.0.1:5000"

    CLIENTS_DATABASE = "/etc/aggrec/clients"

    S3_ENDPOINT_URL = "http://localhost:9000"
    S3_BUCKET = "aggregates"
    S3_BUCKET_CREATE = true
    S3_ACCESS_KEY_ID = "minioadmin"
    S3_SECRET_ACCESS_KEY = "minioadmin"

    MONGODB_HOST = "mongodb://localhost/aggregates"

    MQTT_BROKER = "localhost"
    MQTT_TOPIC = "aggregates"


## API

Documentation at `/docs` and `/redoc`.

## References

- [DNS TAPIR Aggregate Receiver API v1](aggrec/openapi.yaml)
