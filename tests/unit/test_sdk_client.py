import uuid

import httpx
import pytest
import respx

from guardrail_sdk import Decision, GuardrailClient

BASE = "http://gateway.test"
SESSION = uuid.uuid4()


def _decision_body(decision: str, tier: int = 0, fallback: str | None = None) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "decision": decision,
        "risk_tier": tier,
        "risk_score": 0.0,
        "reasons": [{"stage": "policy", "code": "x", "message": "because"}],
        "fallback": fallback,
        "policy_version": "v+abc",
        "latency_ms": 1,
    }


def _tool(name: str, tier: int) -> dict:
    return {"name": name, "tier": tier, "description": "", "fallback": None, "sensitive_args": []}


POLICY_BODY = {
    "version": "v+abc",
    "fail_open_tiers": [0, 1],
    "tools": [_tool("search_docs", 0), _tool("send_email", 2)],
}


@pytest.fixture
def client():
    with GuardrailClient(BASE, "test-key", agent_id="unit") as c:
        yield c


@respx.mock(base_url=BASE)
def test_tool_call_decision_is_parsed_and_key_is_sent(respx_mock, client) -> None:
    route = respx_mock.post("/v1/screen/tool-call").respond(json=_decision_body("DENY", 2))
    decision = client.screen_tool_call(SESSION, "send_email", {"to": "x@evil.io"})

    assert decision.decision is Decision.DENY and not decision.executable
    assert decision.explain() == "because"
    sent = route.calls.last.request
    assert sent.headers["X-Guardrail-Key"] == "test-key"
    assert b'"tool_name":"send_email"' in sent.content


@respx.mock(base_url=BASE)
def test_gateway_error_fails_open_only_for_low_tiers(respx_mock, client) -> None:
    respx_mock.get("/v1/policy").respond(json=POLICY_BODY)
    respx_mock.post("/v1/screen/tool-call").respond(status_code=503)
    client.refresh_policy()

    low = client.screen_tool_call(SESSION, "search_docs", {"query": "q"})
    high = client.screen_tool_call(SESSION, "send_email", {"to": "a@company.com"})
    unknown = client.screen_tool_call(SESSION, "never_heard_of_it", {})

    assert low.decision is Decision.ALLOW and low.gateway_unavailable
    assert high.decision is Decision.DENY and high.risk_tier == 2
    assert unknown.decision is Decision.DENY and unknown.risk_tier == 3


@respx.mock(base_url=BASE)
def test_connection_error_without_policy_cache_fails_closed(respx_mock, client) -> None:
    respx_mock.post("/v1/screen/tool-call").mock(side_effect=httpx.ConnectError("down"))
    decision = client.screen_tool_call(SESSION, "search_docs", {"query": "q"})
    assert decision.decision is Decision.DENY
    assert decision.reasons[0]["code"] == "gateway_unavailable"


@respx.mock(base_url=BASE)
def test_untrusted_content_is_quarantined_when_gateway_down(respx_mock, client) -> None:
    respx_mock.post("/v1/screen/documents").mock(side_effect=httpx.ReadTimeout("slow"))
    respx_mock.post("/v1/screen/input").mock(side_effect=httpx.ReadTimeout("slow"))

    docs = client.screen_documents(SESSION, [("d1", "text"), ("d2", "text")])
    user = client.screen_input(SESSION, "hello")

    assert [d.decision for d in docs] == [Decision.QUARANTINE, Decision.QUARANTINE]
    assert [d.source for d in docs] == ["d1", "d2"]
    assert user.decision is Decision.ALLOW and user.gateway_unavailable


@respx.mock(base_url=BASE)
async def test_async_documents_screening(respx_mock) -> None:
    respx_mock.post("/v1/screen/documents").respond(
        json={
            "results": [
                {"document_id": "d1", "event_id": str(uuid.uuid4()), "decision": "ALLOW"},
                {"document_id": "d2", "event_id": str(uuid.uuid4()), "decision": "QUARANTINE",
                 "reasons": [{"stage": "detector", "code": "injection", "message": "m"}]},
            ],
            "policy_version": "v+abc",
            "latency_ms": 3,
        }
    )  # fmt: skip
    async with GuardrailClient(BASE, "k", agent_id="unit") as client:
        verdicts = await client.ascreen_documents(SESSION, [("d1", "ok"), ("d2", "bad")])
    assert [v.blocked for v in verdicts] == [False, True]
    assert verdicts[1].source == "d2"
