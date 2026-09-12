"""Aggregate independent votes into ALLOW / ALLOW_DEGRADED / DENY.

Rules, in order:
1. Any hard failure (a deterministic check) → DENY. LLM votes can never overrule one.
2. The tier's quorum is met → ALLOW.
3. No hard failure, at least one judge in favour, and the tool declares a safe fallback
   → ALLOW_DEGRADED.
4. Otherwise → DENY.
"""

from __future__ import annotations

from dataclasses import dataclass
from statistics import mean

from gateway.adjudicator.types import Vote
from gateway.schemas import Decision

DETERMINISTIC_CHECKS = frozenset({"provenance", "budget", "invariants"})


@dataclass(frozen=True)
class Thresholds:
    t2_min_aligned: int = 2
    t2_mean_confidence: float = 0.7
    t3_min_confidence: float = 0.85


@dataclass(frozen=True)
class Aggregate:
    decision: Decision
    rule: str


def aggregate(
    tier: int, votes: list[Vote], *, has_fallback: bool, thresholds: Thresholds | None = None
) -> Aggregate:
    t = thresholds or Thresholds()

    for vote in votes:
        if vote.hard and vote.failed:
            return Aggregate(Decision.DENY, f"hard_fail:{vote.check}")

    deterministic_ok = all(v.passed for v in votes if v.check in DETERMINISTIC_CHECKS)
    judges = [v for v in votes if v.check.startswith("alignment")]
    aligned = [v for v in judges if v.passed]
    guardian = next((v for v in votes if v.check == "guardian"), None)

    if tier <= 1:
        quorum = deterministic_ok and len(aligned) * 2 > len(judges)
    elif tier == 2:
        quorum = (
            deterministic_ok
            and len(aligned) >= min(t.t2_min_aligned, len(judges))
            and bool(aligned)
            and mean(v.confidence or 0.0 for v in aligned) >= t.t2_mean_confidence
            and (guardian is None or not guardian.failed)
        )
    else:
        quorum = (
            deterministic_ok
            and bool(judges)
            and len(aligned) == len(judges)
            and min(v.confidence or 0.0 for v in aligned) >= t.t3_min_confidence
            and (guardian is None or guardian.passed)
        )

    if quorum:
        return Aggregate(Decision.ALLOW, f"quorum_met:tier{tier}")
    if has_fallback and aligned:
        return Aggregate(Decision.ALLOW_DEGRADED, f"quorum_not_met:tier{tier}:fallback")
    return Aggregate(Decision.DENY, f"quorum_not_met:tier{tier}")
