"""The adjudicator: runs the four checks on an escalated call and aggregates the votes."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from gateway.adjudicator.aggregator import Thresholds, aggregate
from gateway.adjudicator.alignment import VARIANTS
from gateway.adjudicator.budgets import BudgetLedger, Reservation, invariant_vote
from gateway.adjudicator.packet import JudgePacket
from gateway.adjudicator.provenance import Origin, ProvenanceLedger
from gateway.adjudicator.types import Verdict, Vote, error_vote
from gateway.pipeline.policy import Policy, PolicyResult, ToolPolicy
from gateway.pipeline.taint import TaintState
from gateway.schemas import Decision


class JudgeEnsemble(Protocol):
    async def votes(self, packet: JudgePacket) -> list[Vote]: ...


class RiskGuardian(Protocol):
    async def vote(self, packet: JudgePacket) -> Vote: ...


@dataclass(frozen=True)
class AdjudicationResult:
    decision: Decision
    rule: str
    votes: list[Vote]
    packet: JudgePacket | None
    latency_ms: int
    reservation: Reservation | None = None


class Adjudicator:
    def __init__(
        self,
        policy: Policy,
        ledger: ProvenanceLedger,
        budgets: BudgetLedger,
        judge: JudgeEnsemble | None = None,
        guardian: RiskGuardian | None = None,
        *,
        thresholds: Thresholds | None = None,
        llm_timeout_s: float = 60.0,
        ablate: frozenset[str] = frozenset(),
    ) -> None:
        self.policy = policy
        self.ledger = ledger
        self.budgets = budgets
        self.judge = judge
        self.guardian = guardian
        self.thresholds = thresholds or Thresholds()
        self.llm_timeout_s = llm_timeout_s
        self.ablate = ablate  # evaluation only: see ADJUDICATOR_ABLATE

    def _has_fallback(self, tool: ToolPolicy) -> bool:
        return bool(tool.fallback) and "degraded" not in self.ablate

    async def provenance_vote(
        self,
        session_id: str,
        tool: ToolPolicy,
        args: Mapping[str, Any],
        not_allowlisted: set[str],
    ) -> Vote:
        if "provenance" in self.ablate:
            return Vote("provenance", Verdict.PASS, 1.0, rationale="ablated", raw={"origins": {}})
        origins: dict[str, str] = {}
        hard, soft, notes = False, False, []
        for name, spec in tool.sensitive_args.items():
            if name not in args:
                continue
            origin = await self.ledger.origin_of(session_id, spec.type, args[name])
            origins[name] = origin.value
            allowlisted = spec.allowlist is not None and name not in not_allowlisted
            numeric = spec.type in {"number", "integer"}

            if origin is Origin.UNTRUSTED_FLAGGED:
                hard = True
                notes.append(f"{name} value appears only in content flagged as an injection")
            # An allowlisted *host* doesn't vouch for an attacker-chosen *endpoint* on it (D-030).
            elif origin is Origin.UNTRUSTED_CLEAN and not (
                (allowlisted and spec.type != "url") or numeric
            ):
                soft = True
                notes.append(f"{name} value came from untrusted content, not the user")
            elif origin is Origin.NOVEL and spec.novel == "fail" and not allowlisted:
                hard = True
                notes.append(f"{name} value appears nowhere in the session (invented)")

        verdict = Verdict.FAIL if (hard or soft) else Verdict.PASS
        return Vote(
            "provenance",
            verdict,
            1.0,
            hard=hard,
            rationale="; ".join(notes) or "all sensitive values traced to allowed origins",
            raw={"origins": origins},
        )

    async def _with_timeout(self, awaitable: Any, on_timeout: list[Vote]) -> list[Vote]:
        try:
            result = await asyncio.wait_for(awaitable, self.llm_timeout_s)
        except TimeoutError:
            return on_timeout
        return result if isinstance(result, list) else [result]

    async def _model_votes(
        self, packet: JudgePacket, tool: ToolPolicy, prior: list[Vote]
    ) -> list[Vote]:
        votes: list[Vote] = []
        if self.judge is not None:
            votes += await self._with_timeout(
                self.judge.votes(packet),
                [error_vote(f"alignment_{v}", "timeout") for v in VARIANTS],
            )
        if self.guardian is None:
            return votes
        # The guardian can only downgrade an ALLOW. If the judges already rule ALLOW out
        # (even assuming a guardian pass), its vote can't change the outcome, so skip it.
        # On a 16 GB machine, swapping judge and guardian models costs ~15-20 s.
        hypothetical = aggregate(
            tool.tier,
            [*prior, *votes, Vote("guardian", Verdict.PASS)],
            has_fallback=self._has_fallback(tool),
            thresholds=self.thresholds,
        )
        if hypothetical.decision is not Decision.ALLOW:
            return votes
        votes += await self._with_timeout(
            self.guardian.vote(packet), [error_vote("guardian", "timeout")]
        )
        return votes

    async def adjudicate(
        self,
        session_id: str,
        tool_name: str,
        args: Mapping[str, Any],
        policy_result: PolicyResult,
        taint: TaintState,
    ) -> AdjudicationResult:
        start = time.perf_counter()
        tool = policy_result.tool
        if tool is None:  # unknown tools never reach adjudication, but stay fail-closed
            return AdjudicationResult(Decision.DENY, "unknown_tool", [], None, 0)

        votes = [
            await self.provenance_vote(
                session_id, tool, args, set(policy_result.deferred_allowlist_args)
            ),
            await self.budgets.vote(session_id, tool, args),
            invariant_vote(tool, args),
        ]

        packet = None
        if not any(v.hard and v.failed for v in votes):  # skip LLM cost when already decided
            packet = JudgePacket(
                user_goals=tuple(await self.ledger.goals(session_id)),
                tool_name=tool_name,
                tool_description=tool.description,
                risk_tier=tool.tier,
                args=dict(args),
                taint=taint.summary(),
                provenance=votes[0].raw["origins"],
            )
            votes.extend(await self._model_votes(packet, tool, votes))

        result = aggregate(
            tool.tier, votes, has_fallback=self._has_fallback(tool), thresholds=self.thresholds
        )
        decision, rule, reservation = result.decision, result.rule, None
        if decision is Decision.ALLOW:
            reservation = await self.budgets.reserve(session_id, tool, args)
            if not reservation.ok:
                decision, rule = Decision.DENY, "budget_exhausted_at_reserve"
        return AdjudicationResult(
            decision,
            rule,
            votes,
            packet,
            int((time.perf_counter() - start) * 1000),
            reservation,
        )
