"""Atomic rolling windows. Redis is required when running multiple gateway workers."""

import asyncio
import json
import time
import uuid
from collections import deque
from dataclasses import dataclass

from redis.asyncio import Redis


@dataclass
class Window:
    count: int
    unique_paths: int
    delta_ms: float
    error_ratio: float
    auth_failures: int


class MemoryState:
    def __init__(self, capacity: int = 10000):
        self.windows: dict[str, deque] = {}
        self.statuses: dict[str, deque] = {}
        self.quarantines: dict[str, float] = {}
        self.lock = asyncio.Lock()
        self.capacity = capacity

    async def observe(self, key: str, path: str, limit: int) -> Window:
        async with self.lock:
            now = time.time()
            if key not in self.windows and len(self.windows) >= self.capacity:
                expired = [k for k, v in self.windows.items() if not v or v[-1][0] < now - 60]
                for k in expired:
                    del self.windows[k]
                    self.statuses.pop(k, None)
                if len(self.windows) >= self.capacity:
                    raise RuntimeError("Local state capacity exceeded")
            entries = self.windows.setdefault(key, deque(maxlen=max(limit * 3, 100)))
            while entries and entries[0][0] <= now - 60:
                entries.popleft()
            delta = (now - entries[-1][0]) * 1000 if entries else 60000
            statuses = self.statuses.setdefault(key, deque(maxlen=300))
            while statuses and statuses[0][0] <= now - 60:
                statuses.popleft()
            errors = sum(e[1] >= 400 for e in statuses)
            failures = sum(e[1] == 401 for e in statuses)
            ratio = errors / len(statuses) if statuses else 0
            entries.append((now, path))
            return Window(len(entries), len({e[1] for e in entries}), delta, ratio, failures)

    async def record_status(self, key: str, status: int):
        async with self.lock:
            if key in self.statuses:
                self.statuses[key].append((time.time(), status))

    async def quarantine(self, key: str, seconds: int):
        async with self.lock:
            now = time.time()
            self.quarantines = {k: v for k, v in self.quarantines.items() if v > now}
            if len(self.quarantines) >= self.capacity and key not in self.quarantines:
                raise RuntimeError("Quarantine capacity exceeded")
            self.quarantines[key] = now + seconds

    async def quarantined(self, key: str) -> bool:
        return self.quarantines.get(key, 0) > time.time()

    async def list_quarantines(self):
        now = time.time()
        return [{"identity": k, "expires_at": v} for k, v in self.quarantines.items() if v > now]

    async def release(self, key: str):
        self.quarantines.pop(key, None)

    async def close(self):
        pass


# Each request gets a unique member even when timestamps coincide. Window size is bounded.
OBSERVE = """
local key, now, limit = KEYS[1], tonumber(ARGV[1]), tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - 60)
local old = redis.call('ZRANGE', key, 0, -1)
local paths, errors, failures, last = {}, 0, 0, now - 60
for _, member in ipairs(old) do
  local e = cjson.decode(member)
  paths[e.path] = true
  last = math.max(last, e.time)
end
paths[ARGV[3]] = true
local unique = 0
for _ in pairs(paths) do unique = unique + 1 end
redis.call('ZADD', key, now, ARGV[4])
local count = redis.call('ZCARD', key)
if count > limit * 3 then redis.call('ZREMRANGEBYRANK', key, 0, count - limit * 3 - 1) end
redis.call('EXPIRE', key, 65)
return {count, unique, tostring((now - last) * 1000)}
"""


class RedisState:
    def __init__(self, url: str):
        self.redis = Redis.from_url(url, decode_responses=True, socket_timeout=2)

    async def observe(self, key: str, path: str, limit: int) -> Window:
        now = time.time()
        member = json.dumps({"time": now, "path": path, "id": uuid.uuid4().hex})
        values = await self.redis.eval(OBSERVE, 1, f"zt:window:{key}", now, limit, path, member)
        statuses = await self.redis.lrange(f"zt:status:{key}", 0, -1)
        recent = [json.loads(s) for s in statuses]
        recent = [s for s in recent if s[0] > now - 60]
        return Window(
            int(values[0]),
            int(values[1]),
            float(values[2]),
            sum(s[1] >= 400 for s in recent) / len(recent) if recent else 0,
            sum(s[1] == 401 for s in recent),
        )

    async def record_status(self, key: str, status: int):
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.lpush(f"zt:status:{key}", json.dumps([time.time(), status]))
            pipe.ltrim(f"zt:status:{key}", 0, 299)
            pipe.expire(f"zt:status:{key}", 65)
            await pipe.execute()

    async def quarantine(self, key: str, seconds: int):
        await self.redis.set(f"zt:quarantine:{key}", str(time.time() + seconds), ex=seconds)

    async def quarantined(self, key: str):
        return bool(await self.redis.exists(f"zt:quarantine:{key}"))

    async def list_quarantines(self):
        result = []
        async for key in self.redis.scan_iter(match="zt:quarantine:*", count=100):
            value = await self.redis.get(key)
            if value:
                result.append(
                    {"identity": key.removeprefix("zt:quarantine:"), "expires_at": float(value)}
                )
            if len(result) >= 1000:
                break
        return result

    async def release(self, key: str):
        await self.redis.delete(f"zt:quarantine:{key}")

    async def close(self):
        await self.redis.aclose()
