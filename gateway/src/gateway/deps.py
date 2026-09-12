from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.db.session import get_db
from gateway.pipeline.orchestrator import ScreeningPipeline


def get_pipeline(request: Request) -> ScreeningPipeline:
    return request.app.state.pipeline


DbSession = Annotated[AsyncSession, Depends(get_db)]
Pipeline = Annotated[ScreeningPipeline, Depends(get_pipeline)]
