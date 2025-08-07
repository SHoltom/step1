import time
from backend.redis_client import get_redis
from backend.config import settings

async def is_rate_limited(ip: str) -> bool:
    redis = await get_redis()
    key = f"rl:{ip}"
    now = time.time()
    window = settings.rate_limit_window
    max_attempts = settings.max_attempts_per_window

    pipe = redis.pipeline()
    pipe.zremrangebyscore(key, 0, now - window)
    pipe.zcard(key)
    pipe.zadd(key, {now: now})
    pipe.expire(key, window)
    result = await pipe.execute()

    return result[1] >= max_attempts