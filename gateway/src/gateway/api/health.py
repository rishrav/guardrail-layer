from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from gateway import __version__
from gateway.cache.redis import get_redis
from gateway.db.session import get_db

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness probe: the process is up and serving requests."""
    return {"status": "ok", "version": __version__}


@router.get("/readyz")
async def readyz(
    response: Response, db: Annotated[AsyncSession, Depends(get_db)]
) -> dict[str, str]:
    """Readiness probe: the gateway can't screen (and must fail closed) without these."""
    checks: dict[str, str] = {}
    try:
        await db.execute(text("SELECT 1"))
        checks["postgres"] = "ok"
    except Exception:
        checks["postgres"] = "unavailable"
    try:
        await get_redis().ping()
        checks["redis"] = "ok"
    except Exception:
        checks["redis"] = "unavailable"
    if any(value != "ok" for value in checks.values()):
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return checks
