"""Argument provenance ledger: where did a sensitive value in a tool call come from?

Every piece of content screened for a session is scanned for values (emails, URLs, hosts,
account ids, amounts), and each value is filed into one of three Redis sets:

- ``trusted``: the value appeared in user input.
- ``untrusted``: it appeared in documents or tool outputs that screened clean.
- ``flagged``: it appeared in content that was flagged or quarantined as an injection.

The lookup is purely deterministic, so no prompt can argue its way past it.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Any

from redis.asyncio import Redis

from gateway.adjudicator.extractors import extract_keys, keys_for_arg

SESSION_TTL_S = 24 * 3600
MAX_GOALS = 5
MAX_GOAL_CHARS = 2000


class Origin(StrEnum):
    TRUSTED = "TRUSTED_ORIGIN"
    UNTRUSTED_CLEAN = "UNTRUSTED_CLEAN"
    UNTRUSTED_FLAGGED = "UNTRUSTED_FLAGGED"
    NOVEL = "NOVEL"


class ProvenanceLedger:
    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    @staticmethod
    def _keys(session_id: str) -> dict[str, str]:
        base = f"prov:{session_id}"
        return {
            "trusted": f"{base}:trusted",
            "untrusted": f"{base}:untrusted",
            "flagged": f"{base}:flagged",
            "goals": f"goal:{session_id}",
        }

    async def record(
        self, session_id: str, text: str, *, trusted: bool, flagged: bool = False
    ) -> int:
        values = extract_keys(text)
        keys = self._keys(session_id)
        bucket = "trusted" if trusted else ("flagged" if flagged else "untrusted")
        async with self.redis.pipeline(transaction=True) as pipe:
            if values:
                pipe.sadd(keys[bucket], *values)
                pipe.expire(keys[bucket], SESSION_TTL_S)
            if trusted and text.strip():
                pipe.rpush(keys["goals"], text[:MAX_GOAL_CHARS])
                pipe.ltrim(keys["goals"], -MAX_GOALS, -1)
                pipe.expire(keys["goals"], SESSION_TTL_S)
            await pipe.execute()
        return len(values)

    async def goals(self, session_id: str) -> list[str]:
        """The user's own recent messages: the only intent the judges are allowed to see."""
        return list(await self.redis.lrange(self._keys(session_id)["goals"], 0, -1))

    async def _membership(self, session_id: str, lookups: Iterable[str]) -> dict[str, set[str]]:
        lookups = list(lookups)
        keys = self._keys(session_id)
        found: dict[str, set[str]] = {"trusted": set(), "untrusted": set(), "flagged": set()}
        if not lookups:
            return found
        async with self.redis.pipeline(transaction=False) as pipe:
            for bucket in found:
                pipe.smismember(keys[bucket], lookups)
            results = await pipe.execute()
        for bucket, hits in zip(found, results, strict=True):
            found[bucket] = {key for key, hit in zip(lookups, hits, strict=True) if hit}
        return found

    async def origin_of(self, session_id: str, arg_type: str, value: Any) -> Origin:
        lookups = keys_for_arg(arg_type, value)
        found = await self._membership(session_id, lookups)
        if found["trusted"]:
            return Origin.TRUSTED
        if found["flagged"]:
            return Origin.UNTRUSTED_FLAGGED
        if found["untrusted"]:
            return Origin.UNTRUSTED_CLEAN
        return Origin.NOVEL
