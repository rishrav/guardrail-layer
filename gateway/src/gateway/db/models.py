"""SQLAlchemy ORM models for sessions, audit events, adjudications and benchmarks."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Identity,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSONB, uuid.UUID: UUID(as_uuid=True)}


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(primary_key=True, default=uuid.uuid4)


def _created_at() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AgentSession(Base):
    __tablename__ = "agent_sessions"

    id: Mapped[uuid.UUID] = _uuid_pk()
    agent_id: Mapped[str] = mapped_column(String(128))
    user_id: Mapped[str | None] = mapped_column(String(128))
    taint_level: Mapped[str] = mapped_column(String(16), default="NONE")
    created_at: Mapped[datetime] = _created_at()

    events: Mapped[list[ScreeningEvent]] = relationship(back_populates="session")


class Policy(Base):
    __tablename__ = "policies"

    version: Mapped[str] = mapped_column(String(64), primary_key=True)
    yaml_source: Mapped[str] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = _created_at()


class ScreeningEvent(Base):
    """One screening decision. Append-only and hash-chained, ordered by ``seq``."""

    __tablename__ = "screening_events"

    id: Mapped[uuid.UUID] = _uuid_pk()
    seq: Mapped[int] = mapped_column(BigInteger, Identity(always=True), unique=True, index=True)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agent_sessions.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(32))
    trust_label: Mapped[str] = mapped_column(String(16))
    content_sha256: Mapped[str] = mapped_column(String(64), index=True)
    content_redacted: Mapped[dict[str, Any]] = mapped_column(default=dict)
    decision: Mapped[str] = mapped_column(String(24), index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    reasons: Mapped[dict[str, Any]] = mapped_column(default=dict)
    detector_outputs: Mapped[dict[str, Any]] = mapped_column(default=dict)
    policy_version: Mapped[str | None] = mapped_column(ForeignKey("policies.version"))
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    prev_hash: Mapped[str] = mapped_column(String(64))
    row_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = _created_at()

    session: Mapped[AgentSession] = relationship(back_populates="events")
    tool_call: Mapped[ToolCall | None] = relationship(back_populates="event")


class ToolCall(Base):
    __tablename__ = "tool_calls"

    id: Mapped[uuid.UUID] = _uuid_pk()
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("screening_events.id"), unique=True)
    tool_name: Mapped[str] = mapped_column(String(128), index=True)
    risk_tier: Mapped[int] = mapped_column(Integer)
    args: Mapped[dict[str, Any]] = mapped_column(default=dict)
    execution_mode: Mapped[str] = mapped_column(String(16), default="none")
    outcome: Mapped[str | None] = mapped_column(Text)

    event: Mapped[ScreeningEvent] = relationship(back_populates="tool_call")
    adjudication: Mapped[Adjudication | None] = relationship(back_populates="tool_call")


class Adjudication(Base):
    __tablename__ = "adjudications"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tool_call_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tool_calls.id"), unique=True)
    final_decision: Mapped[str] = mapped_column(String(24))
    rule_fired: Mapped[str] = mapped_column(String(128))
    packet_redacted: Mapped[dict[str, Any]] = mapped_column(default=dict)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = _created_at()

    tool_call: Mapped[ToolCall] = relationship(back_populates="adjudication")
    votes: Mapped[list[AdjudicationVote]] = relationship(back_populates="adjudication")


class AdjudicationVote(Base):
    __tablename__ = "adjudication_votes"

    id: Mapped[uuid.UUID] = _uuid_pk()
    adjudication_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("adjudications.id"), index=True)
    check_name: Mapped[str] = mapped_column(String(64))
    model_name: Mapped[str | None] = mapped_column(String(128))
    model_digest: Mapped[str | None] = mapped_column(String(128))
    prompt_version: Mapped[str | None] = mapped_column(String(32))
    verdict: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float | None] = mapped_column(Float)
    raw_output: Mapped[dict[str, Any]] = mapped_column(default=dict)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)

    adjudication: Mapped[Adjudication] = relationship(back_populates="votes")


class BenchmarkRun(Base):
    __tablename__ = "benchmark_runs"

    id: Mapped[uuid.UUID] = _uuid_pk()
    config_name: Mapped[str] = mapped_column(String(64))
    metrics: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = _created_at()

    results: Mapped[list[BenchmarkResult]] = relationship(back_populates="run")


class BenchmarkResult(Base):
    __tablename__ = "benchmark_results"

    id: Mapped[uuid.UUID] = _uuid_pk()
    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("benchmark_runs.id"), index=True)
    case_id: Mapped[str] = mapped_column(String(128))
    attack_succeeded: Mapped[bool] = mapped_column(Boolean)
    task_completed: Mapped[bool] = mapped_column(Boolean)
    decision: Mapped[str] = mapped_column(String(24))

    run: Mapped[BenchmarkRun] = relationship(back_populates="results")
