import json

import httpx
import pytest

from gateway.models.cassette import CassetteTransport, cassette_key


class CountingTransport(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return httpx.Response(200, json={"message": {"content": f"reply-{self.calls}"}})


def _request(body: str) -> httpx.Request:
    return httpx.Request("POST", "http://ollama.test/api/chat", content=body.encode())


def test_key_ignores_random_delimiters_but_not_content() -> None:
    a = _request('{"user": "DATA-0123456789abcdef\\nhello\\nDATA-0123456789abcdef"}')
    b = _request('{"user": "DATA-fedcba9876543210\\nhello\\nDATA-fedcba9876543210"}')
    c = _request('{"user": "DATA-fedcba9876543210\\nbye\\nDATA-fedcba9876543210"}')
    assert cassette_key(a) == cassette_key(b) != cassette_key(c)


async def test_record_then_replay_round_trip(tmp_path) -> None:
    path = tmp_path / "models.jsonl"
    live = CountingTransport()
    body = '{"prompt": "ARGS-0123456789abcdef x ARGS-0123456789abcdef"}'

    async with httpx.AsyncClient(transport=CassetteTransport(path, "record", live)) as client:
        first = await client.post("http://ollama.test/api/chat", content=body)
        again = await client.post("http://ollama.test/api/chat", content=body)
    assert live.calls == 1  # the second identical request was served from the cassette
    assert first.json() == again.json()
    assert len(path.read_text().splitlines()) == 1
    assert json.loads(path.read_text())["path"] == "/api/chat"

    replay = CassetteTransport(path, "replay", CountingTransport())
    shifted = body.replace("0123456789abcdef", "aaaaaaaaaaaaaaaa")
    async with httpx.AsyncClient(transport=replay) as client:
        hit = await client.post("http://ollama.test/api/chat", content=shifted)
        miss = await client.post("http://ollama.test/api/chat", content='{"prompt": "new"}')
    assert hit.json() == first.json()
    assert miss.status_code == 503
    assert (replay.hits, replay.misses) == (1, 1)


@pytest.mark.parametrize("mode", ["replay"])
async def test_replay_never_touches_the_network(tmp_path, mode) -> None:
    live = CountingTransport()
    transport = CassetteTransport(tmp_path / "empty.jsonl", mode, live)
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await client.post("http://ollama.test/api/chat", content="{}")
    assert resp.status_code == 503 and live.calls == 0
