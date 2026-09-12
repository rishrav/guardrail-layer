import socket
import uuid

import pytest
from redis.asyncio import Redis

from gateway.config import get_settings
from gateway.pipeline.taint import TaintLevel, TaintStore


def _redis_up() -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("localhost", 6379)) == 0


pytestmark = pytest.mark.skipif(not _redis_up(), reason="redis not running")


@pytest.fixture
async def store():
    redis = Redis.from_url(get_settings().redis_url, decode_responses=True)
    yield TaintStore(redis)
    await redis.aclose()


async def test_taint_only_rises_and_accumulates_sources(store: TaintStore) -> None:
    sid = str(uuid.uuid4())
    assert not (await store.get(sid)).tainted

    await store.raise_to(sid, TaintLevel.LOW, source_event="e1", attack_type="exfiltration")
    await store.raise_to(sid, TaintLevel.HIGH, source_event="e2", attack_type="tool_hijack")
    level = await store.raise_to(sid, TaintLevel.LOW, source_event="e3", attack_type="tool_hijack")

    state = await store.get(sid)
    assert level is TaintLevel.HIGH and state.level is TaintLevel.HIGH
    assert state.sources == ("e1", "e2", "e3")
    assert state.summary() == {
        "level": "HIGH",
        "source_count": 3,
        "attack_types": ["exfiltration", "tool_hijack"],
    }
