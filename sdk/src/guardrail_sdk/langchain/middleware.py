"""LangChain 1.x agent middleware that routes every tool call through the Guardrail Gateway.

Hooks:
- ``before_agent``: screens the newest user message, which is the trusted source of intent.
- ``wrap_tool_call``: screens the proposed call, executes the tool only on ALLOW, runs the
  declared safe fallback on ALLOW_DEGRADED, and returns a structured error on DENY. It then
  screens the tool's output before that output re-enters the model context.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from langchain.agents.middleware import AgentMiddleware, ToolCallRequest
from langchain_core.messages import HumanMessage, ToolMessage

from guardrail_sdk.client import GuardrailClient
from guardrail_sdk.types import ContentVerdict, Decision, ToolDecision

Fallback = Callable[[Mapping[str, Any]], str]
ToolResult = Any  # ToolMessage | Command

WITHHELD_OUTPUT = (
    "[guardrail] The tool output was withheld because it appears to contain instructions "
    "aimed at the assistant. Continue the task without it."
)


def message_text(content: Any) -> str:
    """Flatten LangChain message content (a str or a list of content blocks) to text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, Mapping) and block.get("type") == "text":
                parts.append(str(block.get("text", "")))
        return "\n".join(parts)
    return str(content)


class GuardrailMiddleware(AgentMiddleware):
    def __init__(
        self,
        client: GuardrailClient,
        *,
        session_id: uuid.UUID | str | None = None,
        fallbacks: Mapping[str, Fallback] | None = None,
        screen_user_input: bool = True,
        screen_tool_outputs: bool = True,
        on_decision: Callable[[ToolDecision], None] | None = None,
    ) -> None:
        super().__init__()
        self.client = client
        self.session_id = str(session_id or uuid.uuid4())
        self.fallbacks = dict(fallbacks or {})
        self.screen_user_input = screen_user_input
        self.screen_tool_outputs = screen_tool_outputs
        self.on_decision = on_decision

    # ------------------------------------------------------------------ user input
    @staticmethod
    def _latest_user_text(state: Mapping[str, Any]) -> str | None:
        for message in reversed(state.get("messages", [])):
            if isinstance(message, HumanMessage):
                return message_text(message.content)
        return None

    def before_agent(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        text = self._latest_user_text(state)
        if self.screen_user_input and text:
            self.client.screen_input(self.session_id, text)
        return None

    async def abefore_agent(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        text = self._latest_user_text(state)
        if self.screen_user_input and text:
            await self.client.ascreen_input(self.session_id, text)
        return None

    # ------------------------------------------------------------------ tool calls
    @staticmethod
    def _blocked_message(call: Mapping[str, Any], decision: ToolDecision) -> ToolMessage:
        return ToolMessage(
            content=(
                f"[guardrail] Tool call '{call['name']}' was blocked ({decision.decision}). "
                f"Reason: {decision.explain()}. Do not retry this action; tell the user."
            ),
            tool_call_id=call["id"],
            name=call["name"],
            status="error",
        )

    def _degraded_message(self, call: Mapping[str, Any], decision: ToolDecision) -> ToolMessage:
        fallback = self.fallbacks.get(decision.fallback or "")
        if fallback is None:
            body = (
                f"[guardrail] '{call['name']}' was not executed; safe fallback "
                f"'{decision.fallback}' is unavailable. Reason: {decision.explain()}."
            )
        else:
            body = (
                f"[guardrail] '{call['name']}' ran in safe mode ({decision.fallback}), "
                f"not for real. Result: {fallback(call['args'])}. Reason: {decision.explain()}."
            )
        return ToolMessage(content=body, tool_call_id=call["id"], name=call["name"])

    def _withheld(self, call: Mapping[str, Any]) -> ToolMessage:
        return ToolMessage(
            content=WITHHELD_OUTPUT, tool_call_id=call["id"], name=call["name"], status="error"
        )

    def _notify(self, decision: ToolDecision) -> None:
        if self.on_decision is not None:
            self.on_decision(decision)

    def _should_screen_output(self, tool_name: str, result: Any) -> bool:
        return (
            self.screen_tool_outputs
            and isinstance(result, ToolMessage)
            and self.client.screens_output(tool_name)
        )

    def wrap_tool_call(
        self, request: ToolCallRequest, handler: Callable[[ToolCallRequest], ToolResult]
    ) -> ToolResult:
        call = request.tool_call
        decision = self.client.screen_tool_call(self.session_id, call["name"], call["args"])
        self._notify(decision)
        if decision.decision is Decision.ALLOW:
            result = handler(request)
        elif decision.degraded:
            return self._degraded_message(call, decision)
        else:
            return self._blocked_message(call, decision)

        if self._should_screen_output(call["name"], result):
            verdict = self.client.screen_tool_output(
                self.session_id, message_text(result.content), source=call["name"]
            )
            if verdict.blocked:
                return self._withheld(call)
        return result

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolResult]],
    ) -> ToolResult:
        call = request.tool_call
        decision = await self.client.ascreen_tool_call(self.session_id, call["name"], call["args"])
        self._notify(decision)
        if decision.decision is Decision.ALLOW:
            result = await handler(request)
        elif decision.degraded:
            return self._degraded_message(call, decision)
        else:
            return self._blocked_message(call, decision)

        if self._should_screen_output(call["name"], result):
            verdict: ContentVerdict = await self.client.ascreen_tool_output(
                self.session_id, message_text(result.content), source=call["name"]
            )
            if verdict.blocked:
                return self._withheld(call)
        return result
