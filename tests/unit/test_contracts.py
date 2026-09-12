"""The SDK mirrors gateway wire types (D-010); fail loudly if they drift apart."""

from gateway.schemas import Decision as GatewayDecision
from gateway.schemas import ScreenResponse, ToolCallRequest
from guardrail_sdk import Decision as SdkDecision
from guardrail_sdk import GuardrailClient


def test_decision_enums_match() -> None:
    assert {d.value for d in GatewayDecision} == {d.value for d in SdkDecision}


def test_sdk_tool_payload_validates_against_gateway_schema() -> None:
    client = GuardrailClient("http://unused", "k", agent_id="contract", user_id="u1")
    payload = client._tool_payload(
        "5b0e7c0e-2f1a-4d7e-9a53-0d7b4f8a2c11", "send_email", {"to": "a@b.co"}
    )
    ToolCallRequest.model_validate(payload)
    client.close()


def test_sdk_parses_gateway_response_shape() -> None:
    response = ScreenResponse(
        event_id="5b0e7c0e-2f1a-4d7e-9a53-0d7b4f8a2c11",
        decision=GatewayDecision.ALLOW_DEGRADED,
        risk_tier=2,
        fallback="create_draft",
        policy_version="v",
        latency_ms=3,
    )
    decision = GuardrailClient._tool_decision("send_email", response.model_dump(mode="json"))
    assert decision.degraded and decision.fallback == "create_draft"
