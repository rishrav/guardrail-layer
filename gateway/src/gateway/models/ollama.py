"""Minimal async Ollama client: JSON-schema constrained chat and model digests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx


class ModelError(RuntimeError):
    """The model server failed or returned output that doesn't match the schema."""


@dataclass(frozen=True)
class ModelReply:
    data: dict[str, Any]
    model: str
    digest: str | None
    latency_ms: int


class OllamaClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout_s: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._http = httpx.AsyncClient(
            base_url=base_url, timeout=httpx.Timeout(timeout_s, connect=2.0), transport=transport
        )
        self._digests: dict[str, str] = {}

    async def digest(self, model: str) -> str | None:
        """Content digest of the exact local weights, recorded with every vote."""
        if model in self._digests:
            return self._digests[model]
        try:
            resp = await self._http.get("/api/tags")
            resp.raise_for_status()
        except httpx.HTTPError:
            return None
        for entry in resp.json().get("models", []):
            self._digests[entry["name"]] = entry.get("digest", "")
        return self._digests.get(model)

    async def chat_json(
        self,
        model: str,
        *,
        system: str,
        user: str,
        schema: dict[str, Any],
        temperature: float = 0.0,
        seed: int = 7,
    ) -> ModelReply:
        body = {
            "model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "format": schema,
            "stream": False,
            "think": False,
            "options": {"temperature": temperature, "seed": seed},
        }
        try:
            resp = await self._http.post("/api/chat", json=body)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise ModelError(f"{model}: request failed ({type(exc).__name__})") from exc

        payload = resp.json()
        content = payload.get("message", {}).get("content", "")
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ModelError(f"{model}: non-JSON output") from exc
        if not isinstance(data, dict):
            raise ModelError(f"{model}: expected a JSON object")
        missing = [key for key in schema.get("required", []) if key not in data]
        if missing:
            raise ModelError(f"{model}: missing fields {missing}")
        return ModelReply(
            data=data,
            model=model,
            digest=await self.digest(model),
            latency_ms=int(payload.get("total_duration", 0) / 1_000_000),
        )

    async def chat_text(self, model: str, messages: list[dict[str, str]], **options: Any) -> str:
        body = {"model": model, "messages": messages, "stream": False, "options": options}
        try:
            resp = await self._http.post("/api/chat", json=body)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise ModelError(f"{model}: request failed ({type(exc).__name__})") from exc
        return str(resp.json().get("message", {}).get("content", ""))

    async def aclose(self) -> None:
        await self._http.aclose()
