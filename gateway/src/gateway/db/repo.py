"""Audit repository: append-only, hash-chained writes for screening events."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.db.hashchain import GENESIS_HASH, ChainVerification, compute_row_hash, verify_chain
from gateway.db.models import AgentSession, ScreeningEvent, ToolCall
from gateway.db.models import Policy as PolicyRow

if TYPE_CHECKING:
    from gateway.pipeline.policy import Policy

# Arbitrary constant used as the Postgres advisory-lock key for serializing chain appends.
AUDIT_CHAIN_LOCK_KEY = 0x6A7D_1A11

HASHED_FIELDS = (
    "id",
    "session_id",
    "event_type",
    "trust_label",
    "content_sha256",
    "content_redacted",
    "decision",
    "risk_score",
    "reasons",
    "detector_outputs",
    "policy_version",
    "latency_ms",
    "created_at",
)


def _event_record(event: ScreeningEvent) -> dict[str, Any]:
    record = {field: getattr(event, field) for field in HASHED_FIELDS}
    record["prev_hash"] = event.prev_hash
    record["row_hash"] = event.row_hash
    return record


def policy_key(policy: Policy) -> str:
    """Audit key: declared version plus content hash, so an edited-but-unbumped file differs."""
    return f"{policy.version}+{policy.source_sha256[:12]}"


async def register_policy(db: AsyncSession, policy: Policy, yaml_source: str) -> str:
    """Store the policy text and mark it as the single active version."""
    key = policy_key(policy)
    await db.execute(update(PolicyRow).where(PolicyRow.version != key).values(active=False))
    await db.execute(
        insert(PolicyRow)
        .values(version=key, yaml_source=yaml_source, active=True)
        .on_conflict_do_update(index_elements=[PolicyRow.version], set_={"active": True})
    )
    return key


async def record_tool_call(
    db: AsyncSession,
    *,
    event_id: uuid.UUID,
    tool_name: str,
    risk_tier: int,
    args: dict[str, Any],
) -> ToolCall:
    call = ToolCall(
        event_id=event_id,
        tool_name=tool_name,
        risk_tier=risk_tier,
        args=args,
        execution_mode="none",
    )
    db.add(call)
    await db.flush()
    return call


async def ensure_session(
    db: AsyncSession, session_id: uuid.UUID, agent_id: str, user_id: str | None = None
) -> AgentSession:
    existing = await db.get(AgentSession, session_id)
    if existing:
        return existing
    created = AgentSession(id=session_id, agent_id=agent_id, user_id=user_id)
    db.add(created)
    await db.flush()
    return created


async def append_event(db: AsyncSession, **fields: Any) -> ScreeningEvent:
    """Append a screening event to the audit chain.

    A transaction-scoped advisory lock serializes appends so two concurrent requests
    can't both link to the same previous hash. The caller commits.
    """
    await db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": AUDIT_CHAIN_LOCK_KEY})
    prev_hash = await db.scalar(
        select(ScreeningEvent.row_hash).order_by(ScreeningEvent.seq.desc()).limit(1)
    )
    prev_hash = prev_hash or GENESIS_HASH

    event = ScreeningEvent(
        id=fields.pop("id", uuid.uuid4()),
        created_at=datetime.now(UTC),
        content_redacted=fields.pop("content_redacted", {}),
        reasons=fields.pop("reasons", {}),
        detector_outputs=fields.pop("detector_outputs", {}),
        risk_score=float(fields.pop("risk_score", 0.0)),
        latency_ms=int(fields.pop("latency_ms", 0)),
        policy_version=fields.pop("policy_version", None),
        **fields,
    )
    record = {field: getattr(event, field) for field in HASHED_FIELDS}
    event.prev_hash = prev_hash
    event.row_hash = compute_row_hash(prev_hash, record)
    db.add(event)
    await db.flush()
    return event


async def _iter_chain(db: AsyncSession, batch_size: int = 1000) -> AsyncIterator[dict[str, Any]]:
    stream = await db.stream_scalars(
        select(ScreeningEvent).order_by(ScreeningEvent.seq).execution_options(yield_per=batch_size)
    )
    async for event in stream:
        yield _event_record(event)


async def verify_audit_chain(db: AsyncSession) -> ChainVerification:
    records = [record async for record in _iter_chain(db)]
    return verify_chain(records)
