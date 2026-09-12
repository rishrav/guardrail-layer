"""HTTP client for the Guardrail Gateway, with sync and async variants.

Failure semantics (the gateway is unreachable, times out or returns an error):
- tool calls: allowed only if the tool's cached tier is in ``fail_open_tiers``; otherwise
  DENY. Unknown tools are treated as tier 3.
- untrusted content (documents, tool outputs): QUARANTINE by default.
- user input: ALLOW. The user is the principal, and later tool calls are still screened.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any
from uuid import UUID

import httpx

from guardrail_sdk.types import ContentVerdict, Decision, ToolDecision

# Escalated calls wait on local LLM judges (a cold model load alone can take ~15 s).
DEFAULT_TIMEOUT = httpx.Timeout(90.0, connect=2.0)
UNKNOWN_TOOL_TIER = 3


class GuardrailClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        agent_id: str,
        user_id: str | None = None,
        fail_open_tiers: Iterable[int] = (0, 1),
        quarantine_untrusted_on_failure: bool = True,
        timeout: httpx.Timeout | float = DEFAULT_TIMEOUT,
        transport: httpx.BaseTransport | None = None,
        async_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        headers = {"X-Guardrail-Key": api_key}
        self.agent_id = agent_id
        self.user_id = user_id
        self.fail_open_tiers = frozenset(fail_open_tiers)
        self.quarantine_untrusted_on_failure = quarantine_untrusted_on_failure
        self.tool_tiers: dict[str, int] = {}
        self._http = httpx.Client(
            base_url=base_url, headers=headers, timeout=timeout, transport=transport
        )
        self._ahttp = httpx.AsyncClient(
            base_url=base_url, headers=headers, timeout=timeout, transport=async_transport
        )

    # ------------------------------------------------------------------ payloads
    def _session(self, session_id: UUID | str) -> dict[str, Any]:
        return {"session_id": str(session_id), "agent_id": self.agent_id, "user_id": self.user_id}

    def _tool_payload(
        self, session_id: UUID | str, tool_name: str, args: Mapping[str, Any]
    ) -> dict[str, Any]:
        return {**self._session(session_id), "tool_name": tool_name, "args": dict(args)}

    def _content_payload(
        self, session_id: UUID | str, content: str, source: str | None
    ) -> dict[str, Any]:
        return {**self._session(session_id), "content": content, "source": source}

    def _documents_payload(
        self, session_id: UUID | str, documents: Sequence[tuple[str, str]]
    ) -> dict[str, Any]:
        docs = [{"document_id": doc_id, "content": text} for doc_id, text in documents]
        return {**self._session(session_id), "documents": docs}

    # ------------------------------------------------------------------ parsing
    @staticmethod
    def _tool_decision(tool_name: str, data: Mapping[str, Any]) -> ToolDecision:
        return ToolDecision(
            tool_name=tool_name,
            decision=Decision(data["decision"]),
            event_id=UUID(data["event_id"]),
            risk_tier=data.get("risk_tier"),
            reasons=tuple(data.get("reasons", ())),
            fallback=data.get("fallback"),
        )

    @staticmethod
    def _content_verdict(data: Mapping[str, Any], source: str | None = None) -> ContentVerdict:
        return ContentVerdict(
            decision=Decision(data["decision"]),
            event_id=UUID(data["event_id"]),
            source=source or data.get("document_id"),
            reasons=tuple(data.get("reasons", ())),
        )

    def _unavailable_tool(self, tool_name: str, exc: Exception) -> ToolDecision:
        tier = self.tool_tiers.get(tool_name, UNKNOWN_TOOL_TIER)
        fail_open = tier in self.fail_open_tiers
        mode = "open" if fail_open else "closed"
        return ToolDecision(
            tool_name=tool_name,
            decision=Decision.ALLOW if fail_open else Decision.DENY,
            risk_tier=tier,
            reasons=(
                {
                    "stage": "sdk",
                    "code": "gateway_unavailable",
                    "message": f"guardrail gateway unavailable ({type(exc).__name__}); "
                    f"failing {mode} for tier {tier}",
                },
            ),
            gateway_unavailable=True,
        )

    def _unavailable_content(
        self, exc: Exception, *, untrusted: bool, source: str | None = None
    ) -> ContentVerdict:
        block = untrusted and self.quarantine_untrusted_on_failure
        return ContentVerdict(
            decision=Decision.QUARANTINE if block else Decision.ALLOW,
            source=source,
            reasons=(
                {
                    "stage": "sdk",
                    "code": "gateway_unavailable",
                    "message": f"guardrail gateway unavailable ({type(exc).__name__})",
                },
            ),
            gateway_unavailable=True,
        )

    def _store_tiers(self, data: Mapping[str, Any]) -> dict[str, int]:
        self.tool_tiers = {tool["name"]: int(tool["tier"]) for tool in data["tools"]}
        self.fail_open_tiers = frozenset(data.get("fail_open_tiers", self.fail_open_tiers))
        return self.tool_tiers

    # ------------------------------------------------------------------ sync API
    def refresh_policy(self) -> dict[str, int]:
        resp = self._http.get("/v1/policy")
        resp.raise_for_status()
        return self._store_tiers(resp.json())

    def screen_tool_call(
        self, session_id: UUID | str, tool_name: str, args: Mapping[str, Any]
    ) -> ToolDecision:
        try:
            resp = self._http.post(
                "/v1/screen/tool-call", json=self._tool_payload(session_id, tool_name, args)
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            return self._unavailable_tool(tool_name, exc)
        return self._tool_decision(tool_name, resp.json())

    def screen_input(self, session_id: UUID | str, content: str) -> ContentVerdict:
        return self._post_content("/v1/screen/input", session_id, content, None, untrusted=False)

    def screen_tool_output(
        self, session_id: UUID | str, content: str, source: str | None = None
    ) -> ContentVerdict:
        return self._post_content(
            "/v1/screen/tool-output", session_id, content, source, untrusted=True
        )

    def screen_documents(
        self, session_id: UUID | str, documents: Sequence[tuple[str, str]]
    ) -> list[ContentVerdict]:
        try:
            resp = self._http.post(
                "/v1/screen/documents", json=self._documents_payload(session_id, documents)
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            return [
                self._unavailable_content(exc, untrusted=True, source=doc_id)
                for doc_id, _ in documents
            ]
        return [self._content_verdict(item) for item in resp.json()["results"]]

    def _post_content(
        self,
        path: str,
        session_id: UUID | str,
        content: str,
        source: str | None,
        *,
        untrusted: bool,
    ) -> ContentVerdict:
        try:
            resp = self._http.post(path, json=self._content_payload(session_id, content, source))
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            return self._unavailable_content(exc, untrusted=untrusted, source=source)
        return self._content_verdict(resp.json(), source)

    # ------------------------------------------------------------------ async API
    async def arefresh_policy(self) -> dict[str, int]:
        resp = await self._ahttp.get("/v1/policy")
        resp.raise_for_status()
        return self._store_tiers(resp.json())

    async def ascreen_tool_call(
        self, session_id: UUID | str, tool_name: str, args: Mapping[str, Any]
    ) -> ToolDecision:
        try:
            resp = await self._ahttp.post(
                "/v1/screen/tool-call", json=self._tool_payload(session_id, tool_name, args)
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            return self._unavailable_tool(tool_name, exc)
        return self._tool_decision(tool_name, resp.json())

    async def ascreen_input(self, session_id: UUID | str, content: str) -> ContentVerdict:
        return await self._apost_content(
            "/v1/screen/input", session_id, content, None, untrusted=False
        )

    async def ascreen_tool_output(
        self, session_id: UUID | str, content: str, source: str | None = None
    ) -> ContentVerdict:
        return await self._apost_content(
            "/v1/screen/tool-output", session_id, content, source, untrusted=True
        )

    async def ascreen_documents(
        self, session_id: UUID | str, documents: Sequence[tuple[str, str]]
    ) -> list[ContentVerdict]:
        try:
            resp = await self._ahttp.post(
                "/v1/screen/documents", json=self._documents_payload(session_id, documents)
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            return [
                self._unavailable_content(exc, untrusted=True, source=doc_id)
                for doc_id, _ in documents
            ]
        return [self._content_verdict(item) for item in resp.json()["results"]]

    async def _apost_content(
        self,
        path: str,
        session_id: UUID | str,
        content: str,
        source: str | None,
        *,
        untrusted: bool,
    ) -> ContentVerdict:
        try:
            resp = await self._ahttp.post(
                path, json=self._content_payload(session_id, content, source)
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            return self._unavailable_content(exc, untrusted=untrusted, source=source)
        return self._content_verdict(resp.json(), source)

    # ------------------------------------------------------------------ lifecycle
    def close(self) -> None:
        self._http.close()

    async def aclose(self) -> None:
        await self._ahttp.aclose()
        self._http.close()

    def __enter__(self) -> GuardrailClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    async def __aenter__(self) -> GuardrailClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()
