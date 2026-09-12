"""Detection cascade: heuristics → local classifier → LLM (only for ambiguous scores).

Results are cached in Redis by ``(detector, content sha256)``. Detection runs on every
document and tool output, and agents re-read the same chunks constantly.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field

from redis.asyncio import Redis

from gateway.pipeline.detection_types import (
    FLAG_THRESHOLD,
    AsyncDetector,
    AttackType,
    DetectionResult,
    SyncDetector,
)

CACHE_TTL_S = 24 * 3600


@dataclass(frozen=True)
class CascadeResult:
    score: float
    attack_type: AttackType
    results: tuple[DetectionResult, ...] = field(default_factory=tuple)
    decided_by: str = "heuristics"

    @property
    def flagged(self) -> bool:
        return self.score >= FLAG_THRESHOLD

    @property
    def evidence(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(e for r in self.results for e in r.evidence))[:5]

    def to_json(self) -> dict:
        return {
            "score": self.score,
            "flagged": self.flagged,
            "attack_type": self.attack_type.value,
            "decided_by": self.decided_by,
            "results": [r.to_json() for r in self.results],
        }


class DetectionCascade:
    def __init__(
        self,
        heuristics: SyncDetector,
        classifier: SyncDetector | None = None,
        llm: AsyncDetector | None = None,
        redis: Redis | None = None,
        ambiguous_band: tuple[float, float] = (0.3, 0.8),
    ) -> None:
        self.heuristics = heuristics
        self.classifier = classifier
        self.llm = llm
        self.redis = redis
        self.low, self.high = ambiguous_band

    async def _cached(self, detector_name: str, sha: str) -> DetectionResult | None:
        if self.redis is None:
            return None
        try:
            raw = await self.redis.get(f"cache:clf:{detector_name}:{sha}")
        except Exception:
            return None
        if raw is None:
            return None
        data = json.loads(raw)
        data["cached"] = True
        return DetectionResult.from_json(data)

    async def _store(self, result: DetectionResult, sha: str) -> None:
        if self.redis is None or result.error is not None:
            return
        try:
            key = f"cache:clf:{result.detector}:{sha}"
            await self.redis.set(key, json.dumps(result.to_json()), ex=CACHE_TTL_S)
        except Exception:
            return

    async def _run_sync(self, detector: SyncDetector, text: str, sha: str) -> DetectionResult:
        cached = await self._cached(detector.name, sha)
        if cached:
            return cached
        result = await asyncio.to_thread(detector.detect, text)
        await self._store(result, sha)
        return result

    async def _run_async(self, detector: AsyncDetector, text: str, sha: str) -> DetectionResult:
        cached = await self._cached(detector.name, sha)
        if cached:
            return cached
        result = await detector.detect(text)
        await self._store(result, sha)
        return result

    async def detect(self, text: str) -> CascadeResult:
        sha = hashlib.sha256(text.encode()).hexdigest()
        results = [self.heuristics.detect(text)]  # always fresh: microseconds, rules may change
        if self.classifier is not None:
            results.append(await self._run_sync(self.classifier, text, sha))

        valid = [r for r in results if r.error is None]
        top = max(valid, key=lambda r: r.score)
        score, attack, decided_by = top.score, top.attack_type, top.detector

        if self.llm is not None and self.low <= score < self.high:
            verdict = await self._run_async(self.llm, text, sha)
            results.append(verdict)
            if verdict.error is None:
                # The LLM arbitrates only the ambiguous band; a score at or above `high`
                # never reaches this branch, so strong detector hits are never overruled.
                score = verdict.score
                attack = verdict.attack_type if verdict.flagged else attack
                decided_by = verdict.detector

        if score < FLAG_THRESHOLD:
            attack = AttackType.NONE
        return CascadeResult(round(score, 3), attack, tuple(results), decided_by)
