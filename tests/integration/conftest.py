from collections.abc import AsyncIterator

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from gateway.config import get_settings


@pytest.fixture
async def db() -> AsyncIterator[AsyncSession]:
    """A session wrapped in an outer transaction that is always rolled back.

    Requires the compose Postgres (with migrations applied); skips otherwise.
    """
    engine = create_async_engine(get_settings().database_url)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception:
        await engine.dispose()
        pytest.skip("postgres is not available")

    async with engine.connect() as conn:
        trans = await conn.begin()
        session = AsyncSession(bind=conn, expire_on_commit=False)
        try:
            yield session
        finally:
            await session.close()
            await trans.rollback()
    await engine.dispose()
