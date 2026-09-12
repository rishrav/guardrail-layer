from fastapi import APIRouter

from gateway import __version__

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness probe: the process is up and serving requests."""
    return {"status": "ok", "version": __version__}
