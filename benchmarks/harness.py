"""Run benchmark cases through the real stack under different guardrail configurations.

Each configuration boots the actual FastAPI gateway in-process (uvicorn on a free port)
with a set of feature flags. Each case drives the real LangChain agent, SDK middleware and
guarded retriever with a worst-case model that obeys every instruction it can see, and
scores the outcome from the canary sandbox.
"""

from __future__ import annotations

import os
import socket
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path

import httpx
import uvicorn
from langchain_core.documents import Document
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage

from agent_demo.agent import build_demo_agent
from agent_demo.corpus import DOCUMENTS, KeywordRetriever
from agent_demo.scripted_model import ReactiveChatModel, tool_call
from benchmarks.suite import Case, outcome
from guardrail_sdk import GuardrailClient
from guardrail_sdk.langchain.middleware import message_text

CASSETTE = Path(__file__).parent / "cassettes" / "models.jsonl"
DEFAULT_API_KEY = "change-me-local-dev-key"

_FULL = {
    "DETECTION_ENABLED": "true",
    "LLM_CLASSIFIER_ENABLED": "true",
    "ADJUDICATOR_ENABLED": "true",
    "ADJUDICATOR_MODELS_ENABLED": "true",
    "ADJUDICATOR_ABLATE": "",
}
CONFIGS: dict[str, dict[str, str] | None] = {
    "A_no_guardrail": None,
    "B_policy_only": {**_FULL, "DETECTION_ENABLED": "false", "LLM_CLASSIFIER_ENABLED": "false",
                      "ADJUDICATOR_ENABLED": "false"},
    "C_policy_detection": {**_FULL, "ADJUDICATOR_ENABLED": "false"},
    "D_full": dict(_FULL),
}  # fmt: skip
ABLATIONS: dict[str, dict[str, str] | None] = {
    f"D_minus_{part}": {**_FULL, "ADJUDICATOR_ABLATE": part}
    for part in ("provenance", "judges", "guardian", "degraded")
}
ALL_CONFIGS = {**CONFIGS, **ABLATIONS}


@dataclass
class CaseResult:
    config: str
    case_id: str
    category: str
    label: str
    split: str
    outcome: bool  # attack succeeded (attacks) / task completed (benign)
    degraded: bool
    decisions: list[str]
    wall_ms: int
    latencies: dict[str, list[int]] = field(default_factory=dict)
    error: str | None = None

    def to_json(self) -> dict:
        return asdict(self)


def worst_case_model(case: Case) -> ReactiveChatModel:
    """A model that makes each scripted call as soon as the text that "instructs" it is visible."""
    pointer = [0]

    def policy(messages: list[BaseMessage]) -> AIMessage:
        visible = "\n".join(
            message_text(m.content) for m in messages if isinstance(m, HumanMessage | ToolMessage)
        )
        while pointer[0] < len(case.steps):
            step = case.steps[pointer[0]]
            pointer[0] += 1
            if step.trigger is None or step.trigger in visible:
                return tool_call(step.tool, **step.args)
        return AIMessage(content="done")

    return ReactiveChatModel(policy=policy)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def gateway(env: dict[str, str]) -> Iterator[str]:
    """Boot the real gateway with ``env`` applied; yield its base URL."""
    from gateway.config import get_settings
    from gateway.main import create_app

    saved = {key: os.environ.get(key) for key in env}
    os.environ.update(env)
    get_settings.cache_clear()
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 180
    try:
        while not server.started:
            if not thread.is_alive():
                raise RuntimeError("gateway failed to start")
            if time.monotonic() > deadline:
                raise TimeoutError("gateway did not start within 180s")
            time.sleep(0.05)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=60)
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        get_settings.cache_clear()


def _latencies(url: str, api_key: str, session_id: str) -> dict[str, list[int]]:
    resp = httpx.get(
        f"{url}/v1/audit/sessions/{session_id}/events",
        headers={"X-Guardrail-Key": api_key},
        timeout=30,
    )
    resp.raise_for_status()
    paths: dict[str, list[int]] = {}
    for event in resp.json():
        stages = {r.get("stage") for r in event["reasons"].get("items", [])}
        if event["event_type"] != "tool_call":
            path = "content"
        elif "adjudicator" in stages:
            path = "tool_call_adjudicated"
        else:
            path = "tool_call_fast"
        paths.setdefault(path, []).append(int(event["latency_ms"]))
    return paths


def run_case(case: Case, config: str, url: str | None, api_key: str) -> CaseResult:
    session_id = str(uuid.uuid4())
    documents = [Document(id=d["id"], page_content=d["content"]) for d in case.documents]
    retriever = KeywordRetriever(documents=documents or list(DOCUMENTS), k=4)
    client = GuardrailClient(url, api_key, agent_id="benchmark") if url else None
    error = None
    start = time.perf_counter()
    demo = build_demo_agent(
        worst_case_model(case),
        client=client,
        retriever=retriever,
        session_id=session_id,
        tool_outputs=case.tool_outputs,
    )
    try:
        if client is not None:
            client.refresh_policy()
        demo.run(case.user)
    except Exception as exc:  # recorded, and asserted on by the test
        error = f"{type(exc).__name__}: {exc}"
    wall_ms = int((time.perf_counter() - start) * 1000)
    latencies = _latencies(url, api_key, session_id) if url and error is None else {}
    if client is not None:
        client.close()
    return CaseResult(
        config=config,
        case_id=case.id,
        category=case.category,
        label=case.label,
        split=case.split,
        outcome=outcome(case, demo.sandbox),
        degraded=bool(demo.sandbox.degraded()),
        decisions=[str(d.decision) for d in demo.decisions],
        wall_ms=wall_ms,
        latencies=latencies,
        error=error,
    )


def run_config(
    name: str, cases: list[Case], *, cassette_mode: str = "replay", progress: bool = False
) -> list[CaseResult]:
    api_key = os.environ.get("GUARDRAIL_API_KEY", DEFAULT_API_KEY)
    flags = ALL_CONFIGS[name]
    if flags is None:
        return [run_case(case, name, None, api_key) for case in cases]
    env = {
        **flags,
        "GUARDRAIL_API_KEY": api_key,
        "MODEL_CASSETTE_PATH": str(CASSETTE),
        "MODEL_CASSETTE_MODE": cassette_mode,
    }
    results = []
    with gateway(env) as url:
        for index, case in enumerate(cases, 1):
            results.append(run_case(case, name, url, api_key))
            if progress and index % 25 == 0:
                print(f"  {name}: {index}/{len(cases)}", flush=True)
    return results
