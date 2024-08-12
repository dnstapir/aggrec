from fastapi.testclient import TestClient

from aggrec.server import AggrecServer
from aggrec.settings import Settings


def test_server():
    settings = Settings()
    app = AggrecServer(settings)
    _ = TestClient(app)
