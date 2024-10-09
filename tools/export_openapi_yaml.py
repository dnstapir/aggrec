from fastapi.testclient import TestClient

from aggrec.server import AggrecServer

app = AggrecServer()

client = TestClient(app)
response = client.get("/openapi.yaml")
print(response.text)
