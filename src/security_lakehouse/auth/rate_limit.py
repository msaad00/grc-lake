"""Token-bucket rate limiting for the authenticated API surface.

A single-node, in-process limiter that caps request rate per credential so one
caller (or a leaked key) cannot exhaust the server. It is intentionally simple
and dependency-free:

* **Per-credential.** The bucket key is a hash of the bearer token once that
  token has authenticated, otherwise the client host, so one tenant's burst
  never consumes another's budget and unauthenticated tokens cannot mint new
  buckets.
* **Token bucket.** Each key refills at ``rps`` tokens/second up to ``burst``
  capacity, so steady traffic is allowed and short spikes absorb into the burst.
  A denied request reports how long to wait (the ``Retry-After`` value).
* **Bounded memory.** Buckets live in an LRU map capped at ``max_keys`` so the
  limiter itself cannot leak memory under a flood of distinct keys.

Distributed deployments can share one budget across replicas by setting
``TRUSTOPS_API_RATE_LIMIT_REDIS_URL`` (see :mod:`security_lakehouse.auth.rate_limit_redis`).
The in-process limiter remains the default when that URL is unset.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

# Env knobs. Rate limiting is on by default with a generous ceiling — high
# enough that normal interactive + agent traffic never trips it, low enough to
# blunt a runaway loop or a leaked credential.
ENV_RPS = "TRUSTOPS_API_RATE_LIMIT_RPS"
ENV_BURST = "TRUSTOPS_API_RATE_LIMIT_BURST"
ENV_REDIS_URL = "TRUSTOPS_API_RATE_LIMIT_REDIS_URL"
DEFAULT_RPS = 50.0
DEFAULT_BURST = 100
MAX_TRACKED_KEYS = 10_000


class _TokenBucket:
    __slots__ = ("capacity", "refill_rate", "tokens", "updated")

    def __init__(self, capacity: float, refill_rate: float, now: float) -> None:
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.tokens = float(capacity)
        self.updated = now

    def consume(self, now: float, amount: float = 1.0) -> tuple[bool, float]:
        """Take ``amount`` tokens. Returns ``(allowed, retry_after_seconds)``."""
        elapsed = max(0.0, now - self.updated)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.updated = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True, 0.0
        deficit = amount - self.tokens
        retry_after = deficit / self.refill_rate if self.refill_rate > 0 else 1.0
        return False, retry_after


@dataclass(frozen=True)
class RateLimitConfig:
    rps: float = DEFAULT_RPS
    burst: int = DEFAULT_BURST
    enabled: bool = True
    max_keys: int = MAX_TRACKED_KEYS

    @classmethod
    def from_env(cls, env: dict[str, str]) -> RateLimitConfig:
        """Build config from environment. ``rps <= 0`` disables the limiter."""
        try:
            rps = float(env.get(ENV_RPS, DEFAULT_RPS))
        except ValueError:
            rps = DEFAULT_RPS
        try:
            burst = int(env.get(ENV_BURST, DEFAULT_BURST))
        except ValueError:
            burst = DEFAULT_BURST
        enabled = rps > 0 and burst > 0
        return cls(rps=rps, burst=max(1, burst), enabled=enabled)


class RateLimiter:
    """Thread-safe, memory-bounded per-key token-bucket limiter."""

    def __init__(self, config: RateLimitConfig, *, clock=time.monotonic) -> None:
        self._config = config
        self._clock = clock
        self._buckets: OrderedDict[str, _TokenBucket] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    @property
    def config(self) -> RateLimitConfig:
        return self._config

    def check(self, key: str) -> tuple[bool, float]:
        """Charge one request to ``key``. Returns ``(allowed, retry_after_seconds)``."""
        if not self._config.enabled:
            return True, 0.0
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _TokenBucket(self._config.burst, self._config.rps, now)
                self._buckets[key] = bucket
            else:
                self._buckets.move_to_end(key)
            allowed, retry_after = bucket.consume(now)
            # Evict least-recently-used keys so a flood of distinct keys cannot
            # grow the map without bound.
            while len(self._buckets) > self._config.max_keys:
                self._buckets.popitem(last=False)
            return allowed, retry_after
