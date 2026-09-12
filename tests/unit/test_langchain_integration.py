"""The guardrail middleware and retriever wired into a real LangChain agent.

The gateway is mocked with respx, and the model is scripted, so these tests are
deterministic and need no services.
"""

import uuid

import pytest
import respx
from langchain_core.messages import AIMessage, ToolMessage

from agent_demo.agent import build_demo_agent
from agent_demo.corpus import default_retriever
from agent_demo.scripted_model import ScriptedChatModel, tool_call
from guardrail_sdk import GuardrailClient
from guardrail_sdk.langchain import GuardedRetriever

BASE = "http://gateway.test"


def _decision(decision: str, tier: int = 2, fallback: str | None = None) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "decision": decision,
        "risk_tier": tier,
        "reasons": [{"stage": "policy", "code": "c", "message": "policy says so"}],
        "fallback": fallback,
        "policy_version": "v",
        "latency_ms": 1,
    }


def _content(decision: str = "ALLOW") -> dict:
    return {"event_id": str(uuid.uuid4()), "decision": decision, "policy_version": "v",
            "latency_ms": 1, "reasons": []}  # fmt: skip


@pytest.fixture
def client():
    with GuardrailClient(BASE, "k", agent_id="unit") as c:
        yield c


def _tool_messages(result) -> list[ToolMessage]:
    return [m for m in result["messages"] if isinstance(m, ToolMessage)]


def _agent(client, *steps):
    return build_demo_agent(ScriptedChatModel([*steps, AIMessage(content="done")]), client=client)


@respx.mock(base_url=BASE)
def test_denied_tool_never_executes(respx_mock, client) -> None:
    respx_mock.post("/v1/screen/input").respond(json=_content())
    respx_mock.post("/v1/screen/tool-call").respond(json=_decision("DENY", 3))
    demo = _agent(client, tool_call("transfer_funds", account="ACC-EVIL-4242", amount=900))

    result = demo.run("pay the invoice")

    assert demo.sandbox.real("transfer_funds") == []
    [message] = _tool_messages(result)
    assert message.status == "error" and "[guardrail]" in message.content
    assert demo.decisions[0].decision == "DENY"


@respx.mock(base_url=BASE)
def test_allowed_tool_executes_and_output_is_screened(respx_mock, client) -> None:
    respx_mock.post("/v1/screen/input").respond(json=_content())
    respx_mock.post("/v1/screen/tool-call").respond(json=_decision("ALLOW", 0))
    output_route = respx_mock.post("/v1/screen/tool-output").respond(json=_content())
    demo = _agent(client, tool_call("get_weather", city="Paris"))

    demo.run("weather in paris?")

    assert [e.args for e in demo.sandbox.real("get_weather")] == [{"city": "Paris"}]
    assert output_route.called


@respx.mock(base_url=BASE)
def test_quarantined_tool_output_is_withheld_from_model(respx_mock, client) -> None:
    respx_mock.post("/v1/screen/input").respond(json=_content())
    respx_mock.post("/v1/screen/tool-call").respond(json=_decision("ALLOW", 0))
    respx_mock.post("/v1/screen/tool-output").respond(json=_content("QUARANTINE"))
    demo = _agent(client, tool_call("get_weather", city="Paris"))

    result = demo.run("weather?")

    [message] = _tool_messages(result)
    assert "withheld" in message.content and "21C" not in message.content


@respx.mock(base_url=BASE)
def test_degraded_decision_runs_safe_fallback_instead(respx_mock, client) -> None:
    respx_mock.post("/v1/screen/input").respond(json=_content())
    respx_mock.post("/v1/screen/tool-call").respond(
        json=_decision("ALLOW_DEGRADED", 2, fallback="create_draft")
    )
    demo = _agent(client, tool_call("send_email", to="me@gmail.com", subject="Q3"))

    result = demo.run("email me the report")

    assert demo.sandbox.real("send_email") == []
    assert demo.sandbox.degraded("send_email")[0].args["to"] == "me@gmail.com"
    assert "safe mode" in _tool_messages(result)[0].content


@respx.mock(base_url=BASE)
def test_guarded_retriever_drops_quarantined_chunks(respx_mock, client) -> None:
    def verdicts(request):
        import json

        docs = json.loads(request.content)["documents"]
        results = [
            {"document_id": d["document_id"], "event_id": str(uuid.uuid4()),
             "decision": "QUARANTINE" if "Ignore previous" in d["content"] else "ALLOW"}
            for d in docs
        ]  # fmt: skip
        return respx.MockResponse(json={"results": results, "policy_version": "v", "latency_ms": 1})

    respx_mock.post("/v1/screen/documents").mock(side_effect=verdicts)
    retriever = GuardedRetriever(base=default_retriever(k=4), client=client, session_id="s")

    docs = retriever.invoke("Q3 invoice account report")

    ids = [d.id for d in docs]
    assert "vendor-invoice-4471" not in ids and "q3-report" in ids
    assert all(d.metadata["guardrail_trust"] == "UNTRUSTED" for d in docs)


def test_unguarded_baseline_executes_injected_action() -> None:
    demo = build_demo_agent(
        ScriptedChatModel([tool_call("transfer_funds", account="ACC-EVIL-4242", amount=900),
                           AIMessage(content="done")])
    )  # fmt: skip
    demo.run("pay the invoice")
    assert demo.sandbox.real("transfer_funds")[0].args["account"] == "ACC-EVIL-4242"
