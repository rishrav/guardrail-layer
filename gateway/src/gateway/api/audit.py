from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from gateway.api.auth import require_api_key
from gateway.db.models import ScreeningEvent
from gateway.db.repo import verify_audit_chain
from gateway.deps import DbSession

router = APIRouter(prefix="/v1/audit", tags=["audit"], dependencies=[Depends(require_api_key)])


class ChainStatus(BaseModel):
    ok: bool
    checked: int
    broken_at: int | None = None
    reason: str | None = None


class AuditEvent(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    seq: int
    event_type: str
    trust_label: str
    decision: str
    risk_score: float
    reasons: dict[str, Any]
    policy_version: str | None
    latency_ms: int
    row_hash: str
    created_at: datetime


@router.get("/verify", response_model=ChainStatus)
async def verify_chain(db: DbSession):
    """Walk the whole audit chain and report the first broken link, if any."""
    result = await verify_audit_chain(db)
    return ChainStatus(**result.__dict__)


@router.get("/sessions/{session_id}/events", response_model=list[AuditEvent])
async def session_events(session_id: UUID, db: DbSession):
    rows = await db.scalars(
        select(ScreeningEvent)
        .where(ScreeningEvent.session_id == session_id)
        .order_by(ScreeningEvent.seq)
    )
    return rows.all()
