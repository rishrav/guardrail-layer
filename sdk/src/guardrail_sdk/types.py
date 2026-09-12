"""Wire types mirrored from the gateway.

They are deliberately duplicated rather than imported, so agents don't pull in FastAPI or
SQLAlchemy. A contract test keeps the two in sync.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from uuid import UUID


class Decision(StrEnum):
    ALLOW = "ALLOW"
    ALLOW_DEGRADED = "ALLOW_DEGRADED"
    DENY = "DENY"
    ESCALATE = "ESCALATE"
    QUARANTINE = "QUARANTINE"


EXECUTABLE = frozenset({Decision.ALLOW, Decision.ALLOW_DEGRADED})


@dataclass(frozen=True)
class ToolDecision:
    tool_name: str
    decision: Decision
    event_id: UUID | None = None
    risk_tier: int | None = None
    reasons: tuple[dict[str, Any], ...] = ()
    fallback: str | None = None
    gateway_unavailable: bool = False

    @property
    def executable(self) -> bool:
        return self.decision in EXECUTABLE

    @property
    def degraded(self) -> bool:
        return self.decision is Decision.ALLOW_DEGRADED

    def explain(self) -> str:
        messages = [r.get("message", r.get("code", "")) for r in self.reasons]
        return "; ".join(m for m in messages if m) or self.decision.value


@dataclass(frozen=True)
class ContentVerdict:
    decision: Decision
    event_id: UUID | None = None
    source: str | None = None
    reasons: tuple[dict[str, Any], ...] = ()
    gateway_unavailable: bool = False

    @property
    def blocked(self) -> bool:
        return self.decision in {Decision.DENY, Decision.QUARANTINE}
