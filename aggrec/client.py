import argparse
import gzip
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from urllib.parse import urljoin

import cryptography.hazmat.primitives.asymmetric.ec as ec
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
import http_sf
import requests
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from http_message_signatures import HTTPMessageSigner, HTTPSignatureKeyResolver, algorithms

DEFAULT_AGGREGATE_INTERVAL_DURATION = "PT1M"
DEFAULT_CONTENT_TYPE = "application/vnd.apache.parquet"
DEFAULT_COVERED_COMPONENT_IDS = [
    "content-type",
    "content-digest",
    "content-length",
    "aggregate-interval",
]


class MyHTTPSignatureKeyResolver(HTTPSignatureKeyResolver):
    def __init__(self, filename: str) -> None:
        with open(filename, "rb") as fh:
            self.private_key = load_pem_private_key(fh.read(), password=None)
        if isinstance(self.private_key, ed25519.Ed25519PrivateKey):
            self.algorithm = algorithms.ED25519
        elif isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            if not isinstance(self.private_key.curve, ec.SECP256R1):
                raise ValueError("Unsupported curve")
            self.algorithm = algorithms.ECDSA_P256_SHA256
        elif isinstance(self._private_key, rsa.RSAPrivateKey):
            self.algorithm = algorithms.RSA_V1_5_SHA256
        else:
            raise ValueError("Unsupported algorithm")

    def resolve_private_key(self, key_id: str):
        return self.private_key


def main() -> None:
    """Main function"""

    parser = argparse.ArgumentParser(description="Aggregate Sender")

    default_interval = (
        f"{datetime.now(tz=timezone.utc).isoformat(timespec='seconds')}/{DEFAULT_AGGREGATE_INTERVAL_DURATION}"
    )

    parser.add_argument(
        "aggregate",
        metavar="filename",
        help="Aggregate payload",
    )
    parser.add_argument(
        "--interval",
        metavar="interval",
        help=f"Aggregate interval (default {default_interval})",
        default=default_interval,
    )
    parser.add_argument(
        "--tls-cert-file",
        metavar="filename",
        help="TLS client certificate",
        required=False,
    )
    parser.add_argument(
        "--tls-key-file",
        metavar="filename",
        help="TLS client private key",
        required=False,
    )
    parser.add_argument(
        "--http-key-id",
        metavar="id",
        help="HTTP signature key id",
        required=False,
    )
    parser.add_argument(
        "--http-key-file",
        metavar="filename",
        help="HTTP signature key file",
        required=False,
    )
    parser.add_argument(
        "--server",
        metavar="URL",
        help="Aggregate receiver",
        default="http://127.0.0.1:8080",
    )
    parser.add_argument(
        "--type",
        metavar="type",
        choices=["histogram", "vector"],
        help="Aggregate type",
        default="histogram",
    )
    parser.add_argument("--gzip", action="store_true", help="Compress payload using GZIP")
    parser.add_argument(
        "--count",
        metavar="number",
        help="Number of aggregate copies to submit",
        type=int,
        default=1,
    )
    parser.add_argument("--debug", action="store_true", help="Enable debugging")

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    session = requests.Session()

    if args.tls_cert_file and args.tls_key_file:
        session.cert = (args.tls_cert_file, args.tls_key_file)
    elif args.tls_cert_file:
        session.cert = args.tls_cert_file

    covered_component_ids = DEFAULT_COVERED_COMPONENT_IDS

    with open(args.aggregate, "rb") as fp:
        req = requests.Request(
            "POST",
            urljoin(args.server, f"/api/v1/aggregate/{args.type}"),
            data=gzip.compress(fp.read()) if args.gzip else fp.read(),
        )
        if args.gzip:
            req.headers["Content-Encoding"] = "gzip"
            covered_component_ids.append("content-encoding")

    req.headers["Aggregate-Interval"] = args.interval

    req = req.prepare()
    req.headers["X-Request-ID"] = str(uuid.uuid4())
    req.headers["Content-Type"] = DEFAULT_CONTENT_TYPE
    req.headers["Content-Digest"] = http_sf.ser({"sha-256": hashlib.sha256(req.body).digest()})

    if args.http_key_id:
        key_resolver = MyHTTPSignatureKeyResolver(args.http_key_file)
        signer = HTTPMessageSigner(signature_algorithm=key_resolver.algorithm, key_resolver=key_resolver)
        signer.sign(
            req,
            key_id=args.http_key_id,
            label="client",
            covered_component_ids=covered_component_ids,
            include_alg=True,
        )

    for k, v in req.headers.items():
        print(f"{k}: {v}")
    print("")

    for _ in range(args.count):
        resp = session.send(req)
        resp.raise_for_status()
        print(resp)

        if args.count == 1:
            for k, v in resp.headers.items():
                print(f"{k}: {v}")
            print("")
            print(resp.text)
        else:
            print(resp.headers["location"])

    if args.count == 1:
        location = resp.headers["location"]
        resp = session.get(urljoin(args.server, location))
        resp.raise_for_status()
        print(resp)
        print(resp.headers)
        print(json.dumps(json.loads(resp.content), indent=4))

        resp = session.get(resp.json()["content_location"])
        resp.raise_for_status()
        print(resp)
        print(resp.headers)
        print(len(resp.content))


if __name__ == "__main__":
    main()
