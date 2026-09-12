from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from gateway.api.auth import require_api_key
from gateway.config import Settings, get_settings
from gateway.deps import Pipeline

router = APIRouter(prefix="/v1/policy", tags=["policy"], dependencies=[Depends(require_api_key)])


class ToolSummary(BaseModel):
    name: str
    tier: int
    description: str
    fallback: str | None
    sensitive_args: list[str]
    screen_output: bool


class PolicySummary(BaseModel):
    version: str
    fail_open_tiers: list[int]
    tools: list[ToolSummary]


@router.get("", response_model=PolicySummary)
async def get_active_policy(
    pipeline: Pipeline, settings: Annotated[Settings, Depends(get_settings)]
) -> PolicySummary:
    """Tool tiers for SDK clients, so they can fail closed correctly if the gateway goes down."""
    tools = pipeline.policy.document.tools
    return PolicySummary(
        version=pipeline.policy_version,
        fail_open_tiers=sorted(settings.fail_open_tiers),
        tools=[
            ToolSummary(
                name=name,
                tier=tool.tier,
                description=tool.description,
                fallback=tool.fallback,
                sensitive_args=sorted(tool.sensitive_args),
                screen_output=tool.screens_output,
            )
            for name, tool in sorted(tools.items())
        ],
    )
