import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from gateway import __version__
from gateway.api import audit, health, policy, screen
from gateway.cache.redis import get_redis
from gateway.config import Settings, get_settings
from gateway.db import repo
from gateway.db.session import get_engine, get_sessionmaker
from gateway.models.ollama import OllamaClient
from gateway.pipeline.cascade import DetectionCascade
from gateway.pipeline.heuristics import HeuristicDetector
from gateway.pipeline.llm_classifier import LlmInjectionClassifier
from gateway.pipeline.orchestrator import ScreeningPipeline
from gateway.pipeline.policy import Policy, load_policy
from gateway.pipeline.taint import TaintStore

log = logging.getLogger("gateway")


async def build_detection(
    settings: Settings, active_policy: Policy, ollama: OllamaClient
) -> DetectionCascade:
    risky_tools = [name for name, t in active_policy.document.tools.items() if t.tier >= 2]
    classifier = None
    model_dir = Path(settings.injection_model_dir)
    if await asyncio.to_thread((model_dir / "model.onnx").exists):
        from gateway.pipeline.onnx_classifier import OnnxInjectionClassifier

        classifier = await asyncio.to_thread(OnnxInjectionClassifier, model_dir)
    else:
        log.warning(
            "injection classifier weights not found at %s; run scripts/pull_models.sh", model_dir
        )
    llm = (
        LlmInjectionClassifier(ollama, settings.judge_model)
        if settings.llm_classifier_enabled
        else None
    )
    return DetectionCascade(
        HeuristicDetector(risky_tools),
        classifier,
        llm,
        get_redis(),
        (settings.ambiguous_low, settings.ambiguous_high),
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    policy_path = Path(settings.policy_path)
    active_policy = await asyncio.to_thread(load_policy, policy_path)
    yaml_source = await asyncio.to_thread(policy_path.read_text)
    async with get_sessionmaker()() as db:
        await repo.register_policy(db, active_policy, yaml_source)
        await db.commit()

    ollama = OllamaClient(settings.model_base_url, timeout_s=settings.model_timeout_s)
    app.state.pipeline = ScreeningPipeline(
        active_policy,
        detection=await build_detection(settings, active_policy, ollama),
        taint=TaintStore(get_redis()),
    )
    try:
        yield
    finally:
        # Dispose pooled connections and drop cached clients so a new event loop
        # (e.g. the next TestClient) starts clean.
        await ollama.aclose()
        await get_redis().aclose()
        await get_engine().dispose()
        get_redis.cache_clear()
        get_sessionmaker.cache_clear()
        get_engine.cache_clear()


def create_app() -> FastAPI:
    app = FastAPI(title="Guardrail Gateway", version=__version__, lifespan=lifespan)
    app.include_router(health.router)
    app.include_router(screen.router)
    app.include_router(audit.router)
    app.include_router(policy.router)
    return app


app = create_app()
