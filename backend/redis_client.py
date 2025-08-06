import redis.asyncio as aioredis
from config import settings

redis = None

async def get_redis():
    global redis
    if redis is None:
        redis = await aioredis.from_url(
            settings.redis_url,
            encoding="utf8",
            decode_responses=True
        )
    return redis