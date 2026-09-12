from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.db.repo import append_event, ensure_session


async def _seed_event(db: AsyncSession):
    sid = uuid4()
    await ensure_session(db, sid, agent_id="test-agent")
    return await append_event(
        db,
        session_id=sid,
        event_type="tool_call",
        trust_label="TRUSTED",
        content_sha256="b" * 64,
        decision="DENY",
    )


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE screening_events SET decision = 'ALLOW' WHERE id = :id",
        "DELETE FROM screening_events WHERE id = :id",
    ],
)
async def test_audit_rows_cannot_be_mutated(db: AsyncSession, statement: str) -> None:
    event = await _seed_event(db)
    with pytest.raises(DBAPIError, match="append-only"):
        await db.execute(text(statement), {"id": event.id})
