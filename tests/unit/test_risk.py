import pytest

from gateway.pipeline.risk import decide, risk_score
from gateway.schemas import Decision

A, E, D = Decision.ALLOW, Decision.ESCALATE, Decision.DENY


@pytest.mark.parametrize(
    "tier, tainted, flagged, expected",
    [
        # clean session
        (0, False, False, A), (1, False, False, A), (2, False, False, A), (3, False, False, E),
        # tainted session
        (0, True, False, A), (1, True, False, A), (2, True, False, E), (3, True, False, E),
        # call itself flagged (flag dominates taint)
        (0, False, True, A), (1, False, True, E), (2, True, True, E), (3, True, True, D),
    ],
)  # fmt: skip
def test_decision_matrix(tier: int, tainted: bool, flagged: bool, expected: Decision) -> None:
    assert decide(tier, tainted=tainted, flagged=flagged) is expected


def test_invalid_tier_rejected() -> None:
    with pytest.raises(ValueError):
        decide(4, tainted=False, flagged=False)


def test_risk_score_is_monotonic_and_capped() -> None:
    assert risk_score(0, tainted=False, flagged=False) == 0.0
    assert risk_score(2, tainted=True, flagged=False) > risk_score(2, tainted=False, flagged=False)
    assert risk_score(3, tainted=True, flagged=True) == 1.0
