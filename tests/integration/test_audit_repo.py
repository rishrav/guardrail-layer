from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.db.repo import append_event, ensure_session, verify_audit_chain


async def _append(db: AsyncSession, session_id, decision: str):
    return await append_event(
        db,
        session_id=session_id,
        event_type="tool_call",
        trust_label="TRUSTED",
        content_sha256="a" * 64,
        decision=decision,
        risk_score=0.25,
        reasons={"rule": decision.lower(), "nested": {"k": [1, 2]}},
    )


async def test_appended_events_form_verifiable_chain(db: AsyncSession) -> None:
    sid = uuid4()
    await ensure_session(db, sid, agent_id="test-agent")
    first = await _append(db, sid, "ALLOW")
    second = await _append(db, sid, "DENY")

    assert second.prev_hash == first.row_hash
    db.expire_all()  # force a round-trip through Postgres types (JSONB, timestamptz)
    result = await verify_audit_chain(db)
    assert result.ok, result


async def test_tampering_with_a_row_breaks_the_chain(db: AsyncSession) -> None:
    sid = uuid4()
    await ensure_session(db, sid, agent_id="test-agent")
    victim = await _append(db, sid, "DENY")
    await _append(db, sid, "ALLOW")

    # Bypass the append-only trigger the way a privileged attacker could.
    await db.execute(text("SET LOCAL session_replication_role = replica"))
    await db.execute(
        text("UPDATE screening_events SET decision = 'ALLOW' WHERE id = :id"), {"id": victim.id}
    )
    db.expire_all()
    result = await verify_audit_chain(db)
    assert not result.ok
    assert result.reason == "row content was modified"
