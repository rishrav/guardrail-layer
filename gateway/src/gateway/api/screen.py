from fastapi import APIRouter, Depends

from gateway.api.auth import require_api_key
from gateway.deps import DbSession, Pipeline
from gateway.schemas import (
    ContentRequest,
    DocumentsRequest,
    DocumentsResponse,
    EventType,
    ScreenResponse,
    ToolCallRequest,
    TrustLabel,
)

router = APIRouter(prefix="/v1/screen", tags=["screening"], dependencies=[Depends(require_api_key)])


@router.post("/tool-call", response_model=ScreenResponse)
async def screen_tool_call(req: ToolCallRequest, db: DbSession, pipeline: Pipeline):
    """Screen a proposed tool call. The SDK only runs the tool on ALLOW / ALLOW_DEGRADED."""
    response = await pipeline.screen_tool_call(db, req)
    await db.commit()
    return response


@router.post("/input", response_model=ScreenResponse)
async def screen_user_input(req: ContentRequest, db: DbSession, pipeline: Pipeline):
    """Screen a user message. User input is the trusted source of intent."""
    response = await pipeline.screen_content(db, req, EventType.USER_INPUT, TrustLabel.TRUSTED)
    await db.commit()
    return response


@router.post("/tool-output", response_model=ScreenResponse)
async def screen_tool_output(req: ContentRequest, db: DbSession, pipeline: Pipeline):
    """Screen a tool result before it re-enters the model context."""
    response = await pipeline.screen_content(db, req, EventType.TOOL_OUTPUT, TrustLabel.UNTRUSTED)
    await db.commit()
    return response


@router.post("/documents", response_model=DocumentsResponse)
async def screen_documents(req: DocumentsRequest, db: DbSession, pipeline: Pipeline):
    """Screen retrieved documents (RAG chunks) individually."""
    response = await pipeline.screen_documents(db, req)
    await db.commit()
    return response
