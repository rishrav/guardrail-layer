"""Truth-table tests for vote aggregation."""

import pytest

from gateway.adjudicator.aggregator import aggregate
from gateway.adjudicator.types import Verdict, Vote
from gateway.schemas import Decision

P, F, A = Verdict.PASS, Verdict.FAIL, Verdict.ABSTAIN


def deterministic(provenance=P, budget=P, invariants=P, hard=False) -> list[Vote]:
    return [
        Vote("provenance", provenance, 1.0, hard=hard and provenance is F),
        Vote("budget", budget, 1.0),
        Vote("invariants", invariants, 1.0),
    ]


def judges(*verdicts_and_conf: tuple[Verdict, float]) -> list[Vote]:
    names = ["direct", "adversarial", "plan"]
    return [
        Vote(f"alignment_{n}", v, c) for n, (v, c) in zip(names, verdicts_and_conf, strict=False)
    ]


def guardian(verdict: Verdict) -> list[Vote]:
    return [Vote("guardian", verdict)]


STRONG = (P, 0.95)
WEAK = (P, 0.6)
NO = (F, 0.9)


@pytest.mark.parametrize(
    "tier, votes, fallback, expected",
    [
        # hard deterministic failure always wins, even with unanimous judges
        (3, deterministic(F, hard=True) + judges(STRONG, STRONG, STRONG) + guardian(P), True, Decision.DENY),
        (2, deterministic(F, hard=True) + judges(STRONG, STRONG, STRONG), True, Decision.DENY),
        # tier 1: simple majority
        (1, deterministic() + judges(STRONG, NO, STRONG), False, Decision.ALLOW),
        (1, deterministic() + judges(NO, NO, STRONG), False, Decision.DENY),
        # tier 2: 2/3 aligned, mean confidence >= 0.7, guardian not failing
        (2, deterministic() + judges(STRONG, STRONG, NO) + guardian(P), True, Decision.ALLOW),
        (2, deterministic() + judges(WEAK, WEAK, NO) + guardian(P), True, Decision.ALLOW_DEGRADED),
        (2, deterministic() + judges(STRONG, STRONG, STRONG) + guardian(F), True, Decision.ALLOW_DEGRADED),
        (2, deterministic() + judges(STRONG, STRONG, STRONG) + guardian(F), False, Decision.DENY),
        (2, deterministic() + judges(NO, NO, NO) + guardian(P), True, Decision.DENY),
        # soft provenance failure (value from clean untrusted doc) blocks ALLOW, permits fallback
        (2, deterministic(F) + judges(STRONG, STRONG, STRONG) + guardian(P), True, Decision.ALLOW_DEGRADED),
        # tier 3: unanimous, every confidence >= 0.85, guardian must positively pass
        (3, deterministic() + judges(STRONG, STRONG, STRONG) + guardian(P), True, Decision.ALLOW),
        (3, deterministic() + judges(STRONG, STRONG, WEAK) + guardian(P), True, Decision.ALLOW_DEGRADED),
        (3, deterministic() + judges(STRONG, STRONG, STRONG) + guardian(A), True, Decision.ALLOW_DEGRADED),
        (3, deterministic() + judges(STRONG, STRONG, STRONG) + guardian(A), False, Decision.DENY),
        (3, deterministic(F) + judges(STRONG, STRONG, STRONG) + guardian(P), True, Decision.ALLOW_DEGRADED),
        # no judges available (e.g. models down) never yields ALLOW
        (3, deterministic() + guardian(P), True, Decision.DENY),
        (1, deterministic(), False, Decision.DENY),
    ],
)  # fmt: skip
def test_aggregation_truth_table(tier, votes, fallback, expected) -> None:  # noqa: E501
    assert aggregate(tier, votes, has_fallback=fallback).decision is expected


def test_rule_names_are_informative() -> None:
    result = aggregate(3, deterministic(F, hard=True), has_fallback=True)
    assert result.rule == "hard_fail:provenance"
    assert aggregate(3, deterministic() + judges(STRONG, STRONG, STRONG) + guardian(P),
                     has_fallback=False).rule == "quorum_met:tier3"  # fmt: skip
