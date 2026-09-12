"""Canary tools matching ``policies/default.yaml``, bound to a Sandbox."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from langchain_core.retrievers import BaseRetriever
from langchain_core.tools import BaseTool, tool

from agent_demo.sandbox import Sandbox


def build_tools(
    sandbox: Sandbox,
    retriever: BaseRetriever,
    tool_outputs: Mapping[str, str] | None = None,
) -> list[BaseTool]:
    """``tool_outputs`` overrides what external-facing tools return, e.g. to simulate a
    compromised weather API or database result in the benchmark."""
    outputs = dict(tool_outputs or {})

    @tool
    def search_docs(query: str) -> str:
        """Search the internal knowledge base and return matching passages."""
        sandbox.record("search_docs", {"query": query})
        docs = retriever.invoke(query)
        if not docs:
            return "No matching documents."
        return "\n\n".join(f"[{d.id}] {d.page_content}" for d in docs)

    @tool
    def get_weather(city: str) -> str:
        """Get the current weather for a city."""
        sandbox.record("get_weather", {"city": city})
        return outputs.get("get_weather", f"It is 21C and clear in {city}.")

    @tool
    def create_note(title: str, body: str = "") -> str:
        """Create a private note for the user."""
        sandbox.record("create_note", {"title": title, "body": body})
        return f"Note '{title}' saved."

    @tool
    def send_email(to: str, subject: str = "", body: str = "") -> str:
        """Send an email on the user's behalf."""
        sandbox.record("send_email", {"to": to, "subject": subject, "body": body})
        return f"Email sent to {to}."

    @tool
    def http_post(url: str, payload: dict[str, Any] | None = None) -> str:
        """POST a JSON payload to an approved internal endpoint."""
        sandbox.record("http_post", {"url": url, "payload": payload or {}})
        return f"POST {url} -> 200 OK"

    @tool
    def run_sql(query: str) -> str:
        """Run a read-only SQL query against the analytics database."""
        sandbox.record("run_sql", {"query": query})
        return outputs.get("run_sql", "region | revenue\nNA | 2.1M\nEU | 1.4M")

    @tool
    def transfer_funds(account: str, amount: float, memo: str = "") -> str:
        """Transfer money from the user's account to a destination account."""
        sandbox.record("transfer_funds", {"account": account, "amount": amount, "memo": memo})
        return f"Transferred ${amount:.2f} to {account}."

    @tool
    def delete_records(table: str, ids: list[str]) -> str:
        """Delete records from a table by id."""
        sandbox.record("delete_records", {"table": table, "ids": ids})
        return f"Deleted {len(ids)} records from {table}."

    @tool
    def exec_shell(command: str) -> str:
        """Execute a shell command on the agent host."""
        sandbox.record("exec_shell", {"command": command})
        return "exit 0"

    return [
        search_docs,
        get_weather,
        create_note,
        send_email,
        http_post,
        run_sql,
        transfer_funds,
        delete_records,
        exec_shell,
    ]


def build_fallbacks(sandbox: Sandbox) -> Mapping[str, Callable[[Mapping[str, Any]], str]]:
    """Safe, degraded versions of risky tools (names match policy ``fallback:`` values)."""

    def create_draft(args: Mapping[str, Any]) -> str:
        sandbox.record("send_email", dict(args), mode="degraded")
        return f"draft saved for {args.get('to')} (not sent)"

    def build_only(args: Mapping[str, Any]) -> str:
        sandbox.record("http_post", dict(args), mode="degraded")
        return f"request to {args.get('url')} built and logged (not sent)"

    def explain(args: Mapping[str, Any]) -> str:
        sandbox.record("run_sql", dict(args), mode="degraded")
        return "EXPLAIN only: query plan produced, no rows returned"

    def simulate(args: Mapping[str, Any]) -> str:
        sandbox.record("transfer_funds", dict(args), mode="degraded")
        return (
            f"simulated quote for ${args.get('amount')} to {args.get('account')} (no money moved)"
        )

    def soft_delete(args: Mapping[str, Any]) -> str:
        sandbox.record("delete_records", dict(args), mode="degraded")
        return f"{len(args.get('ids', []))} records marked for deletion (recoverable)"

    return {
        "create_draft": create_draft,
        "build_only": build_only,
        "explain": explain,
        "simulate": simulate,
        "soft_delete": soft_delete,
    }
