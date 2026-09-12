"""System-generated tool confirmations are not screened as untrusted content (S-015)."""

import json
import uuid
from pathlib import Path

import pytest
import respx
from langchain_core.messages import AIMessage

from agent_demo.agent import build_demo_agent
from agent_demo.scripted_model import ScriptedChatModel, tool_call
from gateway.pipeline.heuristics import HeuristicDetector
from gateway.pipeline.policy import load_policy
from guardrail_sdk import GuardrailClient

POLICY = load_policy(Path(__file__).parents[2] / "policies" / "default.yaml")
BASE = "http://gateway.test"


def test_policy_marks_action_confirmations_as_system_output() -> None:
    tools = POLICY.document.tools
    for name in ("send_email", "transfer_funds", "delete_records", "create_note"):
        assert not tools[name].screens_output, name
    for name in ("search_docs", "get_weather", "run_sql", "http_post", "exec_shell"):
        assert tools[name].screens_output, name


@pytest.mark.parametrize(
    "text", ["Email sent to me@gmail.com.", "Email the report to me at me@gmail.com."]
)
def test_lone_exfil_phrase_stays_below_the_ambiguous_band(text: str) -> None:
    # Below 0.3 the LLM classifier isn't consulted at all, so no model can over-flag it.
    assert HeuristicDetector().detect(text).score < 0.3


def _tool(name: str, tier: int, screen_output: bool) -> dict:
    return {"name": name, "tier": tier, "description": "", "fallback": None,
            "sensitive_args": [], "screen_output": screen_output}  # fmt: skip


def _event(decision: str = "ALLOW", **extra) -> dict:
    return {"event_id": str(uuid.uuid4()), "decision": decision, "policy_version": "v",
            "latency_ms": 1, "reasons": [], **extra}  # fmt: skip


@respx.mock(base_url=BASE)
def test_middleware_skips_output_screening_for_system_tools(respx_mock) -> None:
    respx_mock.get("/v1/policy").respond(
        json={"version": "v", "fail_open_tiers": [0, 1],
              "tools": [_tool("send_email", 2, False), _tool("get_weather", 0, True)]}
    )  # fmt: skip
    respx_mock.post("/v1/screen/input").respond(json=_event())
    respx_mock.post("/v1/screen/tool-call").respond(json=_event(risk_tier=0))
    outputs = respx_mock.post("/v1/screen/tool-output").respond(json=_event())

    with GuardrailClient(BASE, "k", agent_id="unit") as client:
        client.refresh_policy()
        model = ScriptedChatModel(
            [tool_call("send_email", to="me@gmail.com"), tool_call("get_weather", city="Paris"),
             AIMessage(content="done")]
        )  # fmt: skip
        build_demo_agent(model, client=client).run("email me, then check the weather")

    screened = [json.loads(call.request.content)["source"] for call in outputs.calls]
    assert screened == ["get_weather"]
