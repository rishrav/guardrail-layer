"""A retriever wrapper that screens every retrieved chunk before the model sees it."""

from __future__ import annotations

from typing import Any

from langchain_core.callbacks import (
    AsyncCallbackManagerForRetrieverRun,
    CallbackManagerForRetrieverRun,
)
from langchain_core.documents import Document
from langchain_core.retrievers import BaseRetriever
from pydantic import ConfigDict

from guardrail_sdk.client import GuardrailClient
from guardrail_sdk.types import ContentVerdict


class GuardedRetriever(BaseRetriever):
    """Screens documents from ``base`` and drops any the gateway quarantines.

    Surviving documents are tagged with their screening ``event_id`` in metadata, so a
    decision can be traced back to the exact chunk that influenced it.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    base: BaseRetriever
    client: GuardrailClient
    session_id: str

    @staticmethod
    def _doc_id(doc: Document, index: int) -> str:
        return str(doc.id or doc.metadata.get("id") or f"chunk-{index}")

    def _filter(self, docs: list[Document], verdicts: list[ContentVerdict]) -> list[Document]:
        kept: list[Document] = []
        for doc, verdict in zip(docs, verdicts, strict=True):
            if verdict.blocked:
                continue
            metadata: dict[str, Any] = {
                **doc.metadata,
                "guardrail_event_id": str(verdict.event_id) if verdict.event_id else None,
                "guardrail_trust": "UNTRUSTED",
            }
            kept.append(Document(page_content=doc.page_content, metadata=metadata, id=doc.id))
        return kept

    def _get_relevant_documents(
        self, query: str, *, run_manager: CallbackManagerForRetrieverRun
    ) -> list[Document]:
        docs = self.base.invoke(query, config={"callbacks": run_manager.get_child()})
        pairs = [(self._doc_id(d, i), d.page_content) for i, d in enumerate(docs)]
        return self._filter(docs, self.client.screen_documents(self.session_id, pairs))

    async def _aget_relevant_documents(
        self, query: str, *, run_manager: AsyncCallbackManagerForRetrieverRun
    ) -> list[Document]:
        docs = await self.base.ainvoke(query, config={"callbacks": run_manager.get_child()})
        pairs = [(self._doc_id(d, i), d.page_content) for i, d in enumerate(docs)]
        verdicts = await self.client.ascreen_documents(self.session_id, pairs)
        return self._filter(docs, verdicts)
