from functools import lru_cache

from redis.asyncio import Redis

from gateway.config import get_settings


@lru_cache
def get_redis() -> Redis:
    """Shared async Redis client (connection-pooled)."""
    return Redis.from_url(get_settings().redis_url, decode_responses=True)
