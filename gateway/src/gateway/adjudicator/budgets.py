"""Check B: deterministic budgets and invariants.

Budgets cap the cumulative blast radius of a session (money moved, emails sent, rows
deleted). Reservation is atomic (a Lua script), so parallel calls can't jointly overspend.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis

from gateway.adjudicator.types import Verdict, Vote
from gateway.pipeline.policy import PolicyDocument, ToolPolicy

SESSION_TTL_S = 24 * 3600

_RESERVE = """
local used = tonumber(redis.call('GET', KEYS[1]) or '0')
local cost = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
if used + cost > limit then return {0, tostring(used)} end
local now = redis.call('INCRBYFLOAT', KEYS[1], cost)
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
return {1, tostring(now)}
"""

_SECRET_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),  # common API key prefix
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),  # GitHub tokens
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key)\s*[:=]\s*\S{6,}"),
)


def budget_cost(budget_name: str, args: Mapping[str, Any]) -> float:
    if budget_name.endswith("amount_per_session"):
        return float(args.get("amount", 0) or 0)
    if budget_name.startswith("deletes"):
        return float(len(args.get("ids", []) or []))
    return 1.0


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list | tuple):
        return [s for v in value for s in _strings(v)]
    return []


def invariant_vote(tool: ToolPolicy, args: Mapping[str, Any]) -> Vote:
    """Outbound calls (tier >= 2) must never carry credential-shaped values."""
    if tool.tier < 2:
        return Vote("invariants", Verdict.PASS, 1.0)
    for text in _strings(args):
        for pattern in _SECRET_PATTERNS:
            if pattern.search(text):
                return Vote(
                    "invariants",
                    Verdict.FAIL,
                    1.0,
                    hard=True,
                    rationale="credential-shaped value in outbound arguments",
                    raw={"pattern": pattern.pattern},
                )
    return Vote("invariants", Verdict.PASS, 1.0)


@dataclass(frozen=True)
class Reservation:
    ok: bool
    used: float
    limit: float
    cost: float


class BudgetLedger:
    def __init__(self, redis: Redis, document: PolicyDocument) -> None:
        self.redis = redis
        self.document = document
        self._reserve = redis.register_script(_RESERVE)

    @staticmethod
    def _key(session_id: str, name: str) -> str:
        return f"budget:{session_id}:{name}"

    async def vote(self, session_id: str, tool: ToolPolicy, args: Mapping[str, Any]) -> Vote:
        if not tool.budget:
            return Vote("budget", Verdict.PASS, 1.0, rationale="no budget for tool")
        limit = self.document.budgets[tool.budget]
        cost = budget_cost(tool.budget, args)
        used = float(await self.redis.get(self._key(session_id, tool.budget)) or 0)
        raw = {"budget": tool.budget, "used": used, "cost": cost, "limit": limit}
        if used + cost > limit:
            return Vote(
                "budget",
                Verdict.FAIL,
                1.0,
                hard=True,
                rationale=f"{tool.budget} would exceed {limit:g}",
                raw=raw,
            )
        return Vote("budget", Verdict.PASS, 1.0, raw=raw)

    async def reserve(
        self, session_id: str, tool: ToolPolicy, args: Mapping[str, Any]
    ) -> Reservation:
        """Atomically consume budget for a call that is about to run for real."""
        if not tool.budget:
            return Reservation(True, 0.0, float("inf"), 0.0)
        limit = self.document.budgets[tool.budget]
        cost = budget_cost(tool.budget, args)
        ok, used = await self._reserve(
            keys=[self._key(session_id, tool.budget)], args=[cost, limit, SESSION_TTL_S]
        )
        return Reservation(bool(int(ok)), float(used), limit, cost)
