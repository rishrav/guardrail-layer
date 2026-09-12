import socket

import pytest
from fastapi.testclient import TestClient

from gateway.main import create_app


def _port_open(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("localhost", port)) == 0


@pytest.mark.skipif(not (_port_open(5432) and _port_open(6379)), reason="compose stack not running")
def test_readyz_reports_dependencies_ok() -> None:
    with TestClient(create_app()) as client:
        resp = client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json() == {"postgres": "ok", "redis": "ok"}
