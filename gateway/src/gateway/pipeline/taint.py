"""Per-session taint state in Redis.

A session becomes tainted once flagged content enters the agent's context. Taint only ever
rises within a session, and it expires with the session TTL. The update runs as a Lua script,
so concurrent screens can't overwrite a HIGH level with a stale LOW one.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from redis.asyncio import Redis

SESSION_TTL_S = 24 * 3600
MAX_SOURCES = 50

_RAISE_SCRIPT = """
local current = tonumber(redis.call('HGET', KEYS[1], 'level') or '0')
local proposed = tonumber(ARGV[1])
if proposed > current then
  redis.call('HSET', KEYS[1], 'level', proposed)
  current = proposed
end
redis.call('RPUSH', KEYS[2], ARGV[2])
redis.call('LTRIM', KEYS[2], -tonumber(ARGV[4]), -1)
redis.call('SADD', KEYS[3], ARGV[3])
for i = 1, 3 do redis.call('EXPIRE', KEYS[i], tonumber(ARGV[5])) end
return current
"""


class TaintLevel(IntEnum):
    NONE = 0
    LOW = 1
    HIGH = 2


@dataclass(frozen=True)
class TaintState:
    level: TaintLevel = TaintLevel.NONE
    sources: tuple[str, ...] = ()
    attack_types: tuple[str, ...] = ()

    @property
    def tainted(self) -> bool:
        return self.level > TaintLevel.NONE

    def summary(self) -> dict:
        """Structured summary safe to show judges: never the injected text itself."""
        return {
            "level": self.level.name,
            "source_count": len(self.sources),
            "attack_types": sorted(self.attack_types),
        }


def level_for(score: float) -> TaintLevel:
    if score >= 0.8:
        return TaintLevel.HIGH
    if score >= 0.5:
        return TaintLevel.LOW
    return TaintLevel.NONE


class TaintStore:
    def __init__(self, redis: Redis) -> None:
        self.redis = redis
        self._raise = redis.register_script(_RAISE_SCRIPT)

    @staticmethod
    def _keys(session_id: str) -> list[str]:
        base = f"taint:{session_id}"
        return [base, f"{base}:sources", f"{base}:attacks"]

    async def get(self, session_id: str) -> TaintState:
        level_key, sources_key, attacks_key = self._keys(session_id)
        async with self.redis.pipeline(transaction=False) as pipe:
            pipe.hget(level_key, "level")
            pipe.lrange(sources_key, 0, -1)
            pipe.smembers(attacks_key)
            level, sources, attacks = await pipe.execute()
        return TaintState(
            TaintLevel(int(level or 0)), tuple(sources or ()), tuple(sorted(attacks or ()))
        )

    async def raise_to(
        self, session_id: str, level: TaintLevel, *, source_event: str, attack_type: str
    ) -> TaintLevel:
        if level is TaintLevel.NONE:
            return (await self.get(session_id)).level
        result = await self._raise(
            keys=self._keys(session_id),
            args=[int(level), source_event, attack_type, MAX_SOURCES, SESSION_TTL_S],
        )
        return TaintLevel(int(result))
