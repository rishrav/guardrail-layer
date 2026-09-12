import socket

import pytest
from fastapi.testclient import TestClient

from gateway.config import get_settings
from gateway.main import create_app


def _port_open(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("localhost", port)) == 0


@pytest.mark.skipif(not (_port_open(5432) and _port_open(6379)), reason="compose stack not running")
def test_policy_summary_exposes_tiers_for_sdk_fail_closed() -> None:
    with TestClient(create_app()) as client:
        resp = client.get(
            "/v1/policy", headers={"X-Guardrail-Key": get_settings().api_key.get_secret_value()}
        )
    assert resp.status_code == 200
    body = resp.json()
    tiers = {tool["name"]: tool["tier"] for tool in body["tools"]}
    assert tiers["search_docs"] == 0 and tiers["transfer_funds"] == 3
    assert body["fail_open_tiers"] == [0, 1]
    transfer = next(t for t in body["tools"] if t["name"] == "transfer_funds")
    assert transfer["sensitive_args"] == ["account", "amount"]
