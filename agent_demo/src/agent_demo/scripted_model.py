"""Deterministic chat models for tests and the benchmark.

``ReactiveChatModel`` decides its next message from the conversation so far. The benchmark
uses it to model a *fully compromised* agent that obeys any instruction it reads. That is
the worst case the guardrail must contain, and it's reproducible, unlike sampling a real LLM.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from itertools import count
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import ConfigDict, PrivateAttr

Policy = Callable[[Sequence[BaseMessage]], AIMessage]


class ReactiveChatModel(BaseChatModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    policy: Policy

    @property
    def _llm_type(self) -> str:
        return "reactive-scripted"

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> ReactiveChatModel:
        return self

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=self.policy(messages))])


class ScriptedChatModel(ReactiveChatModel):
    """Replays a fixed list of responses; the last one repeats once exhausted."""

    _index: int = PrivateAttr(default=0)

    def __init__(self, steps: Sequence[AIMessage], **kwargs: Any) -> None:
        steps = list(steps)

        def replay(_: Sequence[BaseMessage]) -> AIMessage:
            message = steps[min(self._index, len(steps) - 1)]
            self._index += 1
            return message

        super().__init__(policy=replay, **kwargs)


_ids = count(1)


def tool_call(name: str, **args: Any) -> AIMessage:
    """An assistant message requesting a single tool call."""
    return AIMessage(
        content="", tool_calls=[{"name": name, "args": args, "id": f"call_{next(_ids)}"}]
    )
