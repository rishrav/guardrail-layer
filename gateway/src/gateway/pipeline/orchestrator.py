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

from gateway.adjudicator.aggregator import DETERMINISTIC_CHECKS
from gateway.adjudicator.budgets import BudgetLedger
from gateway.adjudicator.provenance import ProvenanceLedger
from gateway.adjudicator.service import AdjudicationResult, Adjudicator
from gateway.db import repo
from gateway.pipeline import risk
from gateway.pipeline.cascade import CascadeResult, DetectionCascade
from gateway.pipeline.policy import Policy
from gateway.pipeline.taint import TaintLevel, TaintState, TaintStore, level_for
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


def _string_values(value: Any) -> list[str]:
    """All string leaves of a (possibly nested) argument structure."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _string_values(v)]
    if isinstance(value, list | tuple):
        return [s for v in value for s in _string_values(v)]
    return []


# If Redis (taint state) is unreachable, assume the session is tainted: stricter, not looser.
UNKNOWN_TAINT = TaintState(TaintLevel.LOW, ("taint_store_unavailable",))

EXECUTION_MODE = {Decision.ALLOW: "real", Decision.ALLOW_DEGRADED: "degraded"}


def adjudication_reason(result: AdjudicationResult) -> Reason:
    """A summary the agent may see. Deterministic rationales only, never LLM prose."""
    parts = [v.rationale for v in result.votes if v.failed and v.check in DETERMINISTIC_CHECKS]
    judges = [v for v in result.votes if v.check.startswith("alignment")]
    if judges:
        parts.append(f"alignment {sum(v.passed for v in judges)}/{len(judges)}")
    guardian = next((v for v in result.votes if v.check == "guardian"), None)
    if guardian is not None:
        parts.append(f"guardian {guardian.verdict.value}")
    return Reason(stage="adjudicator", code=result.rule, message="; ".join(parts) or result.rule)


class ScreeningPipeline:
    def __init__(
        self,
        policy: Policy,
        config: PipelineConfig | None = None,
        *,
        detection: DetectionCascade | None = None,
        taint: TaintStore | None = None,
        adjudicator: Adjudicator | None = None,
        provenance: ProvenanceLedger | None = None,
        budgets: BudgetLedger | None = None,
    ) -> None:
        self.policy = policy
        self.config = config or PipelineConfig()
        self.detection = detection
        self.taint = taint
        self.adjudicator = adjudicator
        self.provenance = provenance
        self.budgets = budgets

    async def _record_provenance(
        self, session_id: Any, text: str, *, trusted: bool, flagged: bool
    ) -> bool:
        """File the session's values by origin. A failure here only makes later checks stricter:
        unrecorded values look NOVEL."""
        if self.provenance is None:
            return True
        try:
            await self.provenance.record(str(session_id), text, trusted=trusted, flagged=flagged)
        except Exception:
            return False
        return True

    @property
    def policy_version(self) -> str:
        return repo.policy_key(self.policy)

    async def _session_taint(self, session_id: Any) -> TaintState:
        if self.taint is None:
            return TaintState()
        try:
            return await self.taint.get(str(session_id))
        except Exception:
            return UNKNOWN_TAINT

    async def _detect(self, text: str) -> CascadeResult | None:
        if self.detection is None or not text.strip():
            return None
        return await self.detection.detect(text)

    async def screen_tool_call(self, db: AsyncSession, req: ToolCallRequest) -> ScreenResponse:
        start = time.perf_counter()
        await repo.ensure_session(db, req.session_id, req.agent_id, req.user_id)

        result = self.policy.evaluate_tool_call(req.tool_name, req.args)
        reasons = [
            Reason(stage="policy", code=v.code, message=v.message, arg=v.arg)
            for v in result.violations
        ]
        taint_state = await self._session_taint(req.session_id)
        tainted = taint_state.tainted
        args_detection = await self._detect("\n".join(_string_values(req.args)))
        flagged = bool(args_detection and args_detection.flagged)
        if flagged:
            reasons.append(
                Reason(
                    stage="detection",
                    code="injection_in_arguments",
                    message=f"tool arguments contain {args_detection.attack_type} content",
                )
            )
        if tainted:
            reasons.append(
                Reason(
                    stage="taint",
                    code="session_tainted",
                    message=f"session taint level {taint_state.level.name}",
                )
            )

        adjudication: AdjudicationResult | None = None
        if not result.allowed:
            decision = Decision.DENY
        else:
            decision = risk.decide(result.tier, tainted=tainted, flagged=flagged)
            if decision is Decision.ESCALATE and self.adjudicator is not None:
                adjudication = await self.adjudicator.adjudicate(
                    str(req.session_id), req.tool_name, req.args, result, taint_state
                )
                decision = adjudication.decision
                reasons.append(adjudication_reason(adjudication))
            elif decision is Decision.ESCALATE:
                decision = self.config.unresolved_escalation
                reasons.append(
                    Reason(
                        stage="risk",
                        code="escalation_unresolved",
                        message=f"tier {result.tier} call requires adjudication",
                    )
                )
            elif self.budgets is not None and result.tool is not None and result.tool.budget:
                # Budgets cap every real execution, not just adjudicated ones.
                reservation = await self.budgets.reserve(str(req.session_id), result.tool, req.args)
                if not reservation.ok:
                    decision = Decision.DENY
                    reasons.append(
                        Reason(
                            stage="budget",
                            code="budget_exhausted",
                            message=f"{result.tool.budget} limit {reservation.limit:g} reached",
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
            detector_outputs={
                "arguments": args_detection.to_json() if args_detection else None,
                "taint": taint_state.summary(),
                "adjudication": (
                    {"rule": adjudication.rule, "latency_ms": adjudication.latency_ms}
                    if adjudication
                    else None
                ),
            },
            policy_version=self.policy_version,
            latency_ms=latency,
        )
        tool_call = await repo.record_tool_call(
            db,
            event_id=event.id,
            tool_name=req.tool_name,
            risk_tier=result.tier,
            args=req.args,
            execution_mode=EXECUTION_MODE.get(decision, "none"),
        )
        if adjudication is not None:
            await repo.record_adjudication(db, tool_call_id=tool_call.id, result=adjudication)
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
        source_tool = (
            self.policy.document.tools.get(req.source or "")
            if event_type is EventType.TOOL_OUTPUT
            else None
        )
        # Confirmation text our own action tools produce can't carry third-party instructions;
        # screening it only produced false positives (S-015). It is still audited.
        system_output = source_tool is not None and not source_tool.screens_output
        detection = None if system_output else await self._detect(req.content)
        decision, reasons = Decision.ALLOW, []
        if detection and detection.flagged:
            reasons.append(
                Reason(
                    stage="detection",
                    code="prompt_injection",
                    message=f"{detection.attack_type} detected (score {detection.score:.2f})",
                )
            )
            # The user is the principal: flag and taint their input, but don't block it.
            # Untrusted content is kept out of the model's context entirely.
            if trust_label is TrustLabel.UNTRUSTED:
                decision = Decision.QUARANTINE

        recorded = system_output or await self._record_provenance(
            req.session_id,
            req.content,
            trusted=trust_label is TrustLabel.TRUSTED,
            flagged=bool(detection and detection.flagged),
        )
        if not recorded:
            reasons.append(
                Reason(stage="provenance", code="provenance_unavailable", message="not recorded")
            )
        latency = _elapsed_ms(start)
        event = await repo.append_event(
            db,
            session_id=req.session_id,
            event_type=event_type,
            trust_label=trust_label,
            content_sha256=hashlib.sha256(req.content.encode()).hexdigest(),
            content_redacted={"source": req.source, "length": len(req.content)},
            decision=decision,
            risk_score=detection.score if detection else 0.0,
            reasons={"items": [r.model_dump() for r in reasons]},
            detector_outputs=(
                detection.to_json()
                if detection
                else ({"skipped": "system_output"} if system_output else {})
            ),
            policy_version=self.policy_version,
            latency_ms=latency,
        )
        if detection and detection.flagged and self.taint is not None:
            level = level_for(detection.score)
            try:
                raised = await self.taint.raise_to(
                    str(req.session_id),
                    level,
                    source_event=str(event.id),
                    attack_type=detection.attack_type.value,
                )
                await repo.set_session_taint(db, req.session_id, raised.name)
            except Exception:
                reasons.append(
                    Reason(stage="taint", code="taint_store_unavailable", message="not persisted")
                )
        return ScreenResponse(
            event_id=event.id,
            decision=decision,
            risk_score=detection.score if detection else 0.0,
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
