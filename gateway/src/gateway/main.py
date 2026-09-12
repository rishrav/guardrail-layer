import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from gateway import __version__
from gateway.api import audit, health, policy, screen
from gateway.cache.redis import get_redis
from gateway.config import get_settings
from gateway.db import repo
from gateway.db.session import get_engine, get_sessionmaker
from gateway.pipeline.orchestrator import ScreeningPipeline
from gateway.pipeline.policy import load_policy


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    policy_path = Path(settings.policy_path)
    active_policy = await asyncio.to_thread(load_policy, policy_path)
    yaml_source = await asyncio.to_thread(policy_path.read_text)
    async with get_sessionmaker()() as db:
        await repo.register_policy(db, active_policy, yaml_source)
        await db.commit()
    app.state.pipeline = ScreeningPipeline(active_policy)
    try:
        yield
    finally:
        # Dispose pooled connections and drop cached clients so a new event loop
        # (e.g. the next TestClient) starts clean.
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
