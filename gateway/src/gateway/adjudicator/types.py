from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Verdict(StrEnum):
    PASS = "pass"  # noqa: S105 - a verdict, not a password
    FAIL = "fail"
    ABSTAIN = "abstain"


@dataclass(frozen=True)
class Vote:
    """One independent signal in an adjudication.

    ``hard=True`` failures come from deterministic checks and can't be outvoted.
    """

    check: str
    verdict: Verdict
    confidence: float | None = None
    hard: bool = False
    rationale: str = ""
    model: str | None = None
    model_digest: str | None = None
    prompt_version: str | None = None
    latency_ms: int = 0
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.verdict is Verdict.PASS

    @property
    def failed(self) -> bool:
        return self.verdict is Verdict.FAIL

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        data["verdict"] = self.verdict.value
        return data


def error_vote(check: str, message: str, **meta: Any) -> Vote:
    """Model errors, timeouts and malformed output count as FAIL, never as silent passes."""
    return Vote(check, Verdict.FAIL, 0.0, rationale=f"error: {message}", **meta)
