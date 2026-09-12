"""Pre-adjudication decision matrix: risk tier x session taint x call-level flag.

Kept as explicit tables rather than arithmetic so the policy is readable and testable
cell by cell.
"""

from __future__ import annotations

from gateway.schemas import Decision

A, E, D = Decision.ALLOW, Decision.ESCALATE, Decision.DENY

#                 T0  T1  T2  T3
_CLEAN = (A, A, A, E)
_TAINTED = (A, A, E, E)
_FLAGGED = (A, E, E, D)

_TIER_BASE_SCORE = (0.0, 0.25, 0.5, 0.75)


def decide(tier: int, *, tainted: bool, flagged: bool) -> Decision:
    if not 0 <= tier <= 3:
        raise ValueError(f"invalid risk tier {tier}")
    if flagged:
        return _FLAGGED[tier]
    if tainted:
        return _TAINTED[tier]
    return _CLEAN[tier]


def risk_score(tier: int, *, tainted: bool, flagged: bool) -> float:
    score = _TIER_BASE_SCORE[tier] + (0.15 if tainted else 0.0) + (0.25 if flagged else 0.0)
    return round(min(score, 1.0), 3)
