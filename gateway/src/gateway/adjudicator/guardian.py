"""Check D: IBM Granite Guardian risk vote (a different model family from the judge).

The local ``granite3-guardian:2b`` template has no function-call risk category, so the
proposed action is framed as an assistant turn answering the user's own request and scored
under a policy risk (default ``unethical_behavior``: fraud, theft, abuse). The model
answers "Yes" (risky) or "No".
"""

from __future__ import annotations

import time

from gateway.adjudicator.packet import NO_GOAL, JudgePacket
from gateway.adjudicator.types import Verdict, Vote, error_vote
from gateway.models.ollama import ModelError, OllamaClient

PROMPT_VERSION = "guardian-v1"


class Guardian:
    def __init__(self, client: OllamaClient, model: str, risk: str = "unethical_behavior") -> None:
        self.client = client
        self.model = model
        self.risk = risk

    def messages(self, packet: JudgePacket) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": self.risk},
            {"role": "user", "content": "\n".join(packet.user_goals) or NO_GOAL},
            {
                "role": "assistant",
                "content": f"I will call {packet.tool_name} with {packet.args_json}.",
            },
        ]

    async def vote(self, packet: JudgePacket) -> Vote:
        meta = {"model": self.model, "prompt_version": f"{PROMPT_VERSION}/{self.risk}"}
        start = time.perf_counter()
        try:
            answer = await self.client.chat_text(
                self.model, self.messages(packet), temperature=0, seed=7
            )
        except ModelError as exc:
            return error_vote("guardian", str(exc), **meta)

        normalized = answer.strip().lower()
        if normalized.startswith("yes"):
            verdict, rationale = Verdict.FAIL, f"guardian flagged risk '{self.risk}'"
        elif normalized.startswith("no"):
            verdict, rationale = Verdict.PASS, f"no '{self.risk}' risk detected"
        else:
            verdict, rationale = Verdict.ABSTAIN, "unparseable guardian output"
        return Vote(
            "guardian",
            verdict,
            None,
            rationale=rationale,
            model_digest=await self.client.digest(self.model),
            latency_ms=int((time.perf_counter() - start) * 1000),
            raw={"answer": answer[:50]},
            **meta,
        )
