"""Screening orchestrator: runs the staged pipeline and writes the audit trail.

Stages are injected so the benchmark can run the same code under different configurations
(no guardrail / policy only / + detection / + adjudication).
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from gateway.db import repo
from gateway.pipeline import risk
from gateway.pipeline.policy import Policy
from gateway.schemas import (
    ContentRequest,
    Decision,
    DocumentsRequest,
    DocumentsResponse,
    DocumentVerdict,
    EventType,
    Reason,
    ScreenResponse,
    ToolCallRequest,
    TrustLabel,
)


@dataclass(frozen=True)
class PipelineConfig:
    # What an ESCALATE becomes when no adjudicator is wired in. Fail closed by default.
    unresolved_escalation: Decision = Decision.DENY


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode()).hexdigest()


def _elapsed_ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)


class ScreeningPipeline:
    def __init__(self, policy: Policy, config: PipelineConfig | None = None) -> None:
        self.policy = policy
        self.config = config or PipelineConfig()

    @property
    def policy_version(self) -> str:
        return repo.policy_key(self.policy)

    async def screen_tool_call(self, db: AsyncSession, req: ToolCallRequest) -> ScreenResponse:
        start = time.perf_counter()
        await repo.ensure_session(db, req.session_id, req.agent_id, req.user_id)

        result = self.policy.evaluate_tool_call(req.tool_name, req.args)
        reasons = [
            Reason(stage="policy", code=v.code, message=v.message, arg=v.arg)
            for v in result.violations
        ]
        tainted = False  # session taint arrives with the detection stage
        flagged = False

        if not result.allowed:
            decision = Decision.DENY
        else:
            decision = risk.decide(result.tier, tainted=tainted, flagged=flagged)
            if decision is Decision.ESCALATE:
                decision = self.config.unresolved_escalation
                reasons.append(
                    Reason(
                        stage="risk",
                        code="escalation_unresolved",
                        message=f"tier {result.tier} call requires adjudication",
                    )
                )

        score = risk.risk_score(result.tier, tainted=tainted, flagged=flagged)
        latency = _elapsed_ms(start)
        event = await repo.append_event(
            db,
            session_id=req.session_id,
            event_type=EventType.TOOL_CALL,
            trust_label=TrustLabel.UNTRUSTED,  # proposed by the model, shaped by its context
            content_sha256=_sha256_json({"tool": req.tool_name, "args": req.args}),
            content_redacted={"tool": req.tool_name, "arg_names": sorted(req.args)},
            decision=decision,
            risk_score=score,
            reasons={"items": [r.model_dump() for r in reasons]},
            policy_version=self.policy_version,
            latency_ms=latency,
        )
        await repo.record_tool_call(
            db, event_id=event.id, tool_name=req.tool_name, risk_tier=result.tier, args=req.args
        )
        return ScreenResponse(
            event_id=event.id,
            decision=decision,
            risk_tier=result.tier,
            risk_score=score,
            reasons=reasons,
            fallback=result.tool.fallback if result.tool else None,
            policy_version=self.policy_version,
            latency_ms=latency,
        )

    async def screen_content(
        self,
        db: AsyncSession,
        req: ContentRequest,
        event_type: EventType,
        trust_label: TrustLabel,
    ) -> ScreenResponse:
        start = time.perf_counter()
        await repo.ensure_session(db, req.session_id, req.agent_id, req.user_id)
        decision, reasons = Decision.ALLOW, []  # detectors plug in here
        latency = _elapsed_ms(start)
        event = await repo.append_event(
            db,
            session_id=req.session_id,
            event_type=event_type,
            trust_label=trust_label,
            content_sha256=hashlib.sha256(req.content.encode()).hexdigest(),
            content_redacted={"source": req.source, "length": len(req.content)},
            decision=decision,
            reasons={"items": reasons},
            policy_version=self.policy_version,
            latency_ms=latency,
        )
        return ScreenResponse(
            event_id=event.id,
            decision=decision,
            reasons=reasons,
            policy_version=self.policy_version,
            latency_ms=latency,
        )

    async def screen_documents(self, db: AsyncSession, req: DocumentsRequest) -> DocumentsResponse:
        start = time.perf_counter()
        verdicts = []
        for doc in req.documents:
            single = ContentRequest(
                session_id=req.session_id,
                agent_id=req.agent_id,
                user_id=req.user_id,
                content=doc.content,
                source=doc.document_id,
            )
            resp = await self.screen_content(db, single, EventType.DOCUMENT, TrustLabel.UNTRUSTED)
            verdicts.append(
                DocumentVerdict(
                    document_id=doc.document_id,
                    event_id=resp.event_id,
                    decision=resp.decision,
                    reasons=resp.reasons,
                )
            )
        return DocumentsResponse(
            results=verdicts, policy_version=self.policy_version, latency_ms=_elapsed_ms(start)
        )
