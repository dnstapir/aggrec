# DNS TAPIR Aggregate Receiver

This repository contains the DNS TAPIR Aggregate Receiver, a server component use for submitting and retrieving TAPIR aggregates.

Submitted aggregates are stored in a S3 compatible object store with its metadata stored in MongoDB. New aggregates are announced via MQTT.

Client are assumed to be authenticated using mTLS and all submitted data must be signed using [HTTP Message Signatures](https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures). Public keys for allowed signers are stored in PEM format in the `CLIENTS_DATABASE` directory as `{key_id}.pem`.


## Configuration

The default configuration file is `aggrec.toml`. Example configuration below:

    clients_database = "clients"

    metadata_base_url= "http://127.0.0.1:8080"

    [s3]
    endpoint_url = "http://localhost:9000"
    bucket = "aggregates"
    create_bucket = true
    access_key_id = "minioadmin"
    secret_access_key = "minioadmin"

    [mongodb]
    server =  "mongodb://localhost/aggregates"

    [mqtt]
    broker = "mqtt://localhost"
    topic = "aggregates"

    [otlp]
    spans_endpoint = "http://localhost:4317"
    metrics_endpoint = "http://localhost:4317"
    insecure = true

    [cache]
    size = 1000
    ttl = 300


## API

Documentation at `/docs` and `/redoc`.


## Testing

`docker-compose.yaml` contains a basic stack for running tests.


## References

- [DNS TAPIR Aggregate Receiver API v1](aggrec/openapi.yaml)
