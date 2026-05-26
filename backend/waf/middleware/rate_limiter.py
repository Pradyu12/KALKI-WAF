import time
from typing import Optional

from waf import state
from waf.config import RATE_LIMIT_THRESHOLD, RATE_LIMIT_WINDOW, REDIS_URL

redis_client: Optional["redis.Redis"] = None

try:
    import redis.asyncio as redis

    REDIS_AVAILABLE = True
except ImportError:
    redis = None
    REDIS_AVAILABLE = False
    print("[WARN] redis.asyncio not available - rate limiting will use in-memory fallback")


async def get_redis_client():
    global redis_client
    if redis_client is None:
        if not REDIS_AVAILABLE:
            return None
        try:
            redis_client = redis.from_url(REDIS_URL, decode_responses=True)
            await redis_client.ping()
        except Exception as e:
            print(f"[WARN] Redis unavailable, falling back to in-memory: {e}")
            redis_client = None
    return redis_client


async def check_rate_limit(client_ip: str) -> bool:
    limit = RATE_LIMIT_THRESHOLD
    if state.GLOBAL_POSTURE == "Under Attack":
        limit = 10

    try:
        r = await get_redis_client()
        if r:
            key = f"rate_limit:{client_ip}"
            now = int(time.time())
            pipeline = r.pipeline()
            pipeline.zremrangebyscore(key, 0, now - RATE_LIMIT_WINDOW)
            pipeline.zcard(key)
            pipeline.zadd(key, {str(now): now})
            pipeline.expire(key, RATE_LIMIT_WINDOW)
            results = await pipeline.execute()

            request_count = results[1]
            return not request_count >= limit
    except Exception:
        pass

    current_time = time.time()
    if client_ip not in state.request_history:
        state.request_history[client_ip] = []
    state.request_history[client_ip] = [
        req_time for req_time in state.request_history[client_ip] if current_time - req_time < RATE_LIMIT_WINDOW
    ]
    if len(state.request_history[client_ip]) >= limit:
        return False
    state.request_history[client_ip].append(current_time)
    return True
