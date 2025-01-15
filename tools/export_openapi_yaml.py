from fastapi.testclient import TestClient

from aggrec.server import AggrecServer
from aggrec.settings import Settings
from dnstapir.logging import setup_logging

setup_logging()

app = AggrecServer(settings=Settings())

client = TestClient(app)
response = client.get("/openapi.yaml")
print(response.text)
