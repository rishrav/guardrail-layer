"""Agent factory: the same agent, with or without the guardrail layer."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from langchain.agents import create_agent
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.retrievers import BaseRetriever

from agent_demo.corpus import default_retriever
from agent_demo.sandbox import Sandbox
from agent_demo.tools import build_fallbacks, build_tools
from guardrail_sdk import GuardrailClient, ToolDecision
from guardrail_sdk.langchain import GuardedRetriever, GuardrailMiddleware

SYSTEM_PROMPT = (
    "You are a helpful corporate assistant. Use tools when needed. "
    "Only take actions the user asked for."
)


@dataclass
class DemoAgent:
    agent: Any
    sandbox: Sandbox
    session_id: str
    decisions: list[ToolDecision] = field(default_factory=list)

    def run(self, user_message: str) -> dict[str, Any]:
        return self.agent.invoke({"messages": [{"role": "user", "content": user_message}]})


def build_demo_agent(
    model: BaseChatModel | str,
    *,
    client: GuardrailClient | None = None,
    retriever: BaseRetriever | None = None,
    session_id: str | None = None,
    screen_tool_outputs: bool = True,
    on_decision: Callable[[ToolDecision], None] | None = None,
    tool_outputs: Mapping[str, str] | None = None,
) -> DemoAgent:
    """Build the demo agent. Passing ``client=None`` gives the unguarded baseline."""
    session_id = session_id or str(uuid.uuid4())
    sandbox = Sandbox()
    base_retriever = retriever or default_retriever()
    decisions: list[ToolDecision] = []

    def record(decision: ToolDecision) -> None:
        decisions.append(decision)
        if on_decision is not None:
            on_decision(decision)

    middleware = []
    if client is not None:
        base_retriever = GuardedRetriever(base=base_retriever, client=client, session_id=session_id)
        middleware.append(
            GuardrailMiddleware(
                client,
                session_id=session_id,
                fallbacks=build_fallbacks(sandbox),
                screen_tool_outputs=screen_tool_outputs,
                on_decision=record,
            )
        )

    agent = create_agent(
        model=model,
        tools=build_tools(sandbox, base_retriever, tool_outputs),
        system_prompt=SYSTEM_PROMPT,
        middleware=middleware,
    )
    return DemoAgent(agent=agent, sandbox=sandbox, session_id=session_id, decisions=decisions)
