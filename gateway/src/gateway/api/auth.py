from secrets import compare_digest
from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from gateway.config import Settings, get_settings

API_KEY_HEADER = APIKeyHeader(name="X-Guardrail-Key", auto_error=False)


async def require_api_key(
    key: Annotated[str | None, Security(API_KEY_HEADER)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    """Reject requests without the shared gateway key (constant-time comparison)."""
    expected = settings.api_key.get_secret_value().encode()
    if key is None or not compare_digest(key.encode(), expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or missing API key")
