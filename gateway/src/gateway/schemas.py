"""Public request/response contracts for the screening API (shared with the SDK)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class Decision(StrEnum):
    ALLOW = "ALLOW"
    ALLOW_DEGRADED = "ALLOW_DEGRADED"
    DENY = "DENY"
    ESCALATE = "ESCALATE"
    QUARANTINE = "QUARANTINE"


class EventType(StrEnum):
    USER_INPUT = "user_input"
    DOCUMENT = "document"
    TOOL_CALL = "tool_call"
    TOOL_OUTPUT = "tool_output"


class TrustLabel(StrEnum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"


class SessionRef(BaseModel):
    session_id: UUID
    agent_id: str = Field(min_length=1, max_length=128)
    user_id: str | None = Field(default=None, max_length=128)


class ToolCallRequest(SessionRef):
    tool_name: str = Field(min_length=1, max_length=128)
    args: dict[str, Any] = Field(default_factory=dict)


class ContentRequest(SessionRef):
    content: str = Field(max_length=200_000)
    source: str | None = Field(default=None, max_length=256)


class DocumentIn(BaseModel):
    document_id: str = Field(max_length=256)
    content: str = Field(max_length=200_000)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DocumentsRequest(SessionRef):
    documents: list[DocumentIn] = Field(max_length=100)


class Reason(BaseModel):
    stage: str
    code: str
    message: str
    arg: str | None = None


class ScreenResponse(BaseModel):
    event_id: UUID
    decision: Decision
    risk_tier: int | None = None
    risk_score: float = 0.0
    reasons: list[Reason] = Field(default_factory=list)
    fallback: str | None = None
    policy_version: str
    latency_ms: int


class DocumentVerdict(BaseModel):
    document_id: str
    event_id: UUID
    decision: Decision
    reasons: list[Reason] = Field(default_factory=list)


class DocumentsResponse(BaseModel):
    results: list[DocumentVerdict]
    policy_version: str
    latency_ms: int
