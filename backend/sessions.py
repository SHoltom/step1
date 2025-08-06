import secrets
from redis_client import get_redis
from config import settings

async def create_session(user_dict: dict) -> str:
    session_id = secrets.token_urlsafe(48)
    redis = await get_redis()
    await redis.setex(
        f"session:{session_id}",
        settings.session_ttl_seconds,
        session_id
    )
    return session_id

async def is_session_valid(session_id: str) -> bool:
    if not session_id:
        return False
    redis = await get_redis()
    return await redis.exists(f"session:{session_id}") > 0

async def destroy_session(session_id: str):
    redis = await get_redis()
    await redis.delete(f"session:{session_id}")