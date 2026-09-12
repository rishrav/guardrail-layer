from fastapi import FastAPI

from gateway import __version__
from gateway.api import health


def create_app() -> FastAPI:
    app = FastAPI(title="Guardrail Gateway", version=__version__)
    app.include_router(health.router)
    return app


app = create_app()
