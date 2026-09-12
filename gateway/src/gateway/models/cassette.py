"""Record/replay transport for model calls, for reproducible, free benchmark runs.

Requests are keyed by method, path and body. The random per-call delimiters
(``DATA-<hex>`` / ``ARGS-<hex>``) are normalized first, so a replay matches its recording.
- ``record``: replay a hit, call the real server on a miss and append it.
- ``replay``: hits only. A miss returns HTTP 503, which the callers treat as a model
  error (fail closed), and is counted.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from pathlib import Path
from typing import Literal

import httpx

# No leading \b: inside a JSON body the marker follows an escaped newline ("\nDATA-..."),
# and "n" + "D" is not a word boundary.
_MARKERS = re.compile(rb"(DATA|ARGS)-[0-9a-f]{16}(?![0-9a-f])")


def cassette_key(request: httpx.Request) -> str:
    body = _MARKERS.sub(rb"\1-MARKER", request.content or b"")
    digest = hashlib.sha256(request.method.encode() + request.url.path.encode() + body)
    return digest.hexdigest()


class CassetteTransport(httpx.AsyncBaseTransport):
    def __init__(
        self,
        path: str | Path,
        mode: Literal["record", "replay"] = "replay",
        inner: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.path = Path(path)
        self.mode = mode
        self.inner = inner or httpx.AsyncHTTPTransport()
        self.hits = 0
        self.misses = 0
        self._lock = threading.Lock()
        self._store: dict[str, dict] = {}
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    entry = json.loads(line)
                    self._store[entry["key"]] = entry

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        key = cassette_key(request)
        entry = self._store.get(key)
        if entry is not None:
            self.hits += 1
            return httpx.Response(entry["status"], json=entry["json"], request=request)
        if self.mode == "replay":
            self.misses += 1
            return httpx.Response(503, json={"error": "cassette miss"}, request=request)

        response = await self.inner.handle_async_request(request)
        await response.aread()
        entry = {"key": key, "path": request.url.path, "status": response.status_code,
                 "json": json.loads(response.content or b"null")}  # fmt: skip
        with self._lock:
            self._store[key] = entry
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
        self.misses += 1
        return httpx.Response(entry["status"], json=entry["json"], request=request)

    async def aclose(self) -> None:
        await self.inner.aclose()
