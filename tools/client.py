import hashlib
import os
from urllib.parse import urljoin

import http_sfv
import requests
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from http_message_signatures import (
    HTTPMessageSigner,
    HTTPSignatureKeyResolver,
    algorithms,
)

ENDPOINT = "http://127.0.0.1:5000"
KEY_ID = "test"
LABEL = "tapir"


class MyHTTPSignatureKeyResolver(HTTPSignatureKeyResolver):
    def resolve_private_key(self, key_id: str):
        with open(f"{key_id}-private.pem", "rb") as fh:
            return load_pem_private_key(fh.read(), password=None)


session = requests.Session()

key_resolver = MyHTTPSignatureKeyResolver()
signer = HTTPMessageSigner(
    signature_algorithm=algorithms.ECDSA_P256_SHA256, key_resolver=key_resolver
)

req = requests.Request(
    "POST", urljoin(ENDPOINT, "/aggregate/histogram"), data=os.urandom(1024)
)
req = req.prepare()
req.headers["Content-Type"] = "application/binary"
req.headers["Content-Digest"] = str(
    http_sfv.Dictionary({"sha-256": hashlib.sha256(req.body).digest()})
)

signer.sign(
    req,
    key_id=KEY_ID,
    label=LABEL,
    covered_component_ids=("content-type", "content-digest", "content-length"),
    include_alg=True,
)

print(req.headers)
print("")

# create aggregate
resp = session.send(req)
resp.raise_for_status()
print(resp)
print(resp.text)

# fetch metadata
resp2 = session.get(urljoin(ENDPOINT, resp.headers.get("Location")))
print(resp2)
print(resp2.headers)
print(resp2.text)

# fetch payload
payload_location = resp2.json()["content_location"]
resp3 = session.get(payload_location)
print(resp3)
print(resp3.headers)
print(len(resp3.content), "bytes received")
