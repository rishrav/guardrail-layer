"""Shared result types for injection detectors."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any, Protocol


class AttackType(StrEnum):
    DIRECT_OVERRIDE = "direct_override"
    INDIRECT_INSTRUCTION = "indirect_instruction"
    EXFILTRATION = "exfiltration"
    TOOL_HIJACK = "tool_hijack"
    JAILBREAK_ROLEPLAY = "jailbreak_roleplay"
    OBFUSCATED = "obfuscated"
    NONE = "none"


FLAG_THRESHOLD = 0.5


@dataclass(frozen=True)
class DetectionResult:
    detector: str
    score: float  # 0..1 likelihood the text contains an injection
    attack_type: AttackType = AttackType.NONE
    evidence: tuple[str, ...] = ()
    latency_ms: int = 0
    cached: bool = False
    error: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def flagged(self) -> bool:
        return self.error is None and self.score >= FLAG_THRESHOLD

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        data["attack_type"] = self.attack_type.value
        data["evidence"] = list(self.evidence)
        return data

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> DetectionResult:
        return cls(
            detector=data["detector"],
            score=float(data["score"]),
            attack_type=AttackType(data.get("attack_type", "none")),
            evidence=tuple(data.get("evidence", ())),
            latency_ms=int(data.get("latency_ms", 0)),
            cached=bool(data.get("cached", False)),
            error=data.get("error"),
            meta=dict(data.get("meta", {})),
        )


class SyncDetector(Protocol):
    name: str

    def detect(self, text: str) -> DetectionResult: ...


class AsyncDetector(Protocol):
    name: str

    async def detect(self, text: str) -> DetectionResult: ...
