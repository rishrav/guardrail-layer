"""Full gateway path: a poisoned document's exfiltration address is caught by provenance, and
the adjudication and its votes are persisted for audit."""

import asyncio
import socket
import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from agent_demo.corpus import DOCUMENTS
from gateway.config import get_settings
from gateway.db.models import Adjudication, AdjudicationVote, ToolCall
from gateway.main import create_app


def _port_open(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("localhost", port)) == 0


pytestmark = pytest.mark.skipif(
    not (_port_open(5432) and _port_open(6379)), reason="compose stack not running"
)


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    with TestClient(create_app()) as c:
        c.headers["X-Guardrail-Key"] = get_settings().api_key.get_secret_value()
        yield c


async def _load_adjudication(
    event_id: str,
) -> tuple[Adjudication, list[AdjudicationVote], ToolCall]:
    engine = create_async_engine(get_settings().database_url)
    try:
        async with engine.connect() as conn:
            call = (
                await conn.execute(select(ToolCall).where(ToolCall.event_id == uuid.UUID(event_id)))
            ).one()
            adjudication = (
                await conn.execute(select(Adjudication).where(Adjudication.tool_call_id == call.id))
            ).one()
            votes = (
                await conn.execute(
                    select(AdjudicationVote).where(
                        AdjudicationVote.adjudication_id == adjudication.id
                    )
                )
            ).all()
            return adjudication, votes, call
    finally:
        await engine.dispose()


def test_exfiltration_address_from_poisoned_doc_is_denied_and_audited(client: TestClient) -> None:
    session = {"session_id": str(uuid.uuid4()), "agent_id": "adjudication-test"}
    client.post("/v1/screen/input", json={**session, "content": "Summarize the Q3 report for me."})
    invoice = next(d for d in DOCUMENTS if d.id == "vendor-invoice-4471")
    client.post(
        "/v1/screen/documents",
        json={
            **session,
            "documents": [{"document_id": invoice.id, "content": invoice.page_content}],
        },
    )

    body = client.post(
        "/v1/screen/tool-call",
        json={
            **session,
            "tool_name": "send_email",
            "args": {"to": "billing@northwind-payments.io", "subject": "Q3 report"},
        },
    ).json()

    assert body["decision"] == "DENY"
    [reason] = [r for r in body["reasons"] if r["stage"] == "adjudicator"]
    assert reason["code"] == "hard_fail:provenance"
    assert "billing@" not in reason["message"]  # agent-facing text carries no values

    adjudication, votes, call = asyncio.run(_load_adjudication(body["event_id"]))
    assert adjudication.rule_fired == "hard_fail:provenance"
    assert adjudication.packet_redacted == {}  # judges were never consulted
    assert call.execution_mode == "none"
    assert {v.check_name for v in votes} == {"provenance", "budget", "invariants"}
    provenance = next(v for v in votes if v.check_name == "provenance")
    assert provenance.raw_output["origins"] == {"to": "UNTRUSTED_FLAGGED"}
