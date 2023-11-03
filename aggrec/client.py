import argparse
import gzip
import hashlib
import json
import logging
from urllib.parse import urljoin

import http_sfv
import requests
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from http_message_signatures import (
    HTTPMessageSigner,
    HTTPSignatureKeyResolver,
    algorithms,
)

DEFAULT_CONTENT_TYPE = "application/vnd.apache.parquet"
DEFAULT_COVERED_COMPONENT_IDS = ["content-type", "content-digest", "content-length"]


class MyHTTPSignatureKeyResolver(HTTPSignatureKeyResolver):
    def __init__(self, filename: str) -> None:
        self.filename = filename

    def resolve_private_key(self, key_id: str):
        with open(self.filename, "rb") as fh:
            return load_pem_private_key(fh.read(), password=None)


def main() -> None:
    """Main function"""

    parser = argparse.ArgumentParser(description="Aggregate Sender")

    parser.add_argument(
        "aggregate",
        metavar="filename",
        help="Aggregate payload",
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
    parser.add_argument(
        "--gzip", action="store_true", help="Compress payload using GZIP"
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

    req = req.prepare()
    req.headers["Content-Type"] = DEFAULT_CONTENT_TYPE
    req.headers["Content-Digest"] = str(
        http_sfv.Dictionary({"sha-256": hashlib.sha256(req.body).digest()})
    )

    if args.http_key_id:
        key_resolver = MyHTTPSignatureKeyResolver(args.http_key_file)
        signer = HTTPMessageSigner(
            signature_algorithm=algorithms.ECDSA_P256_SHA256, key_resolver=key_resolver
        )
        signer.sign(
            req,
            key_id=args.http_key_id,
            label="client",
            covered_component_ids=covered_component_ids,
            include_alg=True,
        )

    print(req.headers)
    print("")

    resp = session.send(req)
    resp.raise_for_status()

    print(resp)
    print(resp.headers)
    print(resp.text)

    location = resp.headers["location"]
    resp = session.get(urljoin(args.server, location))
    resp.raise_for_status()
    print(resp)
    print(resp.headers)
    print(json.loads(resp.content))

    resp = session.get(resp.json()["content_location"])
    resp.raise_for_status()
    print(resp)
    print(resp.headers)
    print(len(resp.content))


if __name__ == "__main__":
    main()
