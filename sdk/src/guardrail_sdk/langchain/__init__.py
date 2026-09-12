"""LangChain integration: agent middleware and a guarded retriever.

Requires the ``langchain`` extra: ``pip install guardrail-sdk[langchain]``.
"""

from guardrail_sdk.langchain.middleware import GuardrailMiddleware
from guardrail_sdk.langchain.retriever import GuardedRetriever

__all__ = ["GuardedRetriever", "GuardrailMiddleware"]
