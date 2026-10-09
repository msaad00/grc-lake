"""Redis-backed token-bucket rate limiter for multi-replica deployments."""

from __future__ import annotations

import time
from typing import Protocol

from security_lakehouse.auth.rate_limit import RateLimitConfig
from security_lakehouse.runtime_environment import runtime_env

# Atomic token-bucket check/set across processes. Keys are prefixed per limiter.
_TOKEN_BUCKET_LUA = """
local tokens_key = KEYS[1]
local last_key = KEYS[2]
local now = tonumber(ARGV[1])
local rps = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])

local tokens = tonumber(redis.call('GET', tokens_key))
if tokens == nil then
  tokens = burst
end
local last = tonumber(redis.call('GET', last_key))
if last == nil then
  last = now
end

local elapsed = math.max(0, now - last)
tokens = math.min(burst, tokens + elapsed * rps)

if tokens >= 1 then
  tokens = tokens - 1
  redis.call('SET', tokens_key, tokens)
  redis.call('SET', last_key, now)
  return {1, 0}
end

local retry_after = (1 - tokens) / rps
redis.call('SET', tokens_key, tokens)
redis.call('SET', last_key, now)
return {0, retry_after}
"""


class RateLimiterBackend(Protocol):
    @property
    def enabled(self) -> bool:
        pass

    def check(self, key: str) -> tuple[bool, float]:
        pass


__all__ = ["RateLimiterBackend", "RedisRateLimiter", "build_rate_limiter"]


class RedisRateLimiter:
    """Shared token-bucket limiter backed by Redis."""

    def __init__(
        self,
        config: RateLimitConfig,
        redis_url: str,
        *,
        clock=time.monotonic,
        key_prefix: str = "trustops:rate:",
        client=None,
    ) -> None:
        import redis

        self._config = config
        self._clock = clock
        self._prefix = key_prefix
        self._client = client if client is not None else redis.Redis.from_url(redis_url, decode_responses=False)

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    @property
    def config(self) -> RateLimitConfig:
        return self._config

    def check(self, key: str) -> tuple[bool, float]:
        if not self._config.enabled:
            return True, 0.0
        now = self._clock()
        tokens_key = f"{self._prefix}{key}:tokens"
        last_key = f"{self._prefix}{key}:last"
        allowed_raw, retry_raw = self._client.eval(
            _TOKEN_BUCKET_LUA,
            2,
            tokens_key,
            last_key,
            now,
            self._config.rps,
            self._config.burst,
        )
        allowed = int(allowed_raw) == 1
        retry_after = float(retry_raw)
        return allowed, max(0.0, retry_after)


def build_rate_limiter(config: RateLimitConfig, env: dict[str, str]) -> RateLimiterBackend:
    """Return in-memory or Redis limiter based on ``GRC_LAKE_API_RATE_LIMIT_REDIS_URL``."""
    env = runtime_env(env)
    from security_lakehouse.auth.rate_limit import ENV_REDIS_URL, RateLimiter

    redis_url = (env.get(ENV_REDIS_URL) or "").strip()
    if redis_url:
        return RedisRateLimiter(config, redis_url)
    return RateLimiter(config)
