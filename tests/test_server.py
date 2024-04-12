from fastapi.testclient import TestClient

from aggrec.server import AggrecServer


def test_server():
    app = AggrecServer()
    _ = TestClient(app)
