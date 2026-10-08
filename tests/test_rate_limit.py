"""API rate limiting: token-bucket unit behaviour + the 429 middleware path."""

from __future__ import annotations

import os
from http import HTTPStatus
from pathlib import Path

import pytest

from security_lakehouse.auth.rate_limit import RateLimitConfig, RateLimiter

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from fastapi.testclient import TestClient

from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake


class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


# --- token bucket ------------------------------------------------------------


def test_burst_then_throttle_then_refill() -> None:
    clock = _Clock()
    limiter = RateLimiter(RateLimitConfig(rps=2.0, burst=3), clock=clock)

    # The burst capacity is allowed immediately.
    assert [limiter.check("k")[0] for _ in range(3)] == [True, True, True]
    # The 4th in the same instant is denied with a positive retry-after.
    allowed, retry_after = limiter.check("k")
    assert allowed is False
    assert retry_after > 0

    # After enough time to refill one token (rps=2 -> 0.5s/token), one passes.
    clock.advance(0.5)
    assert limiter.check("k")[0] is True
    assert limiter.check("k")[0] is False


def test_keys_are_isolated() -> None:
    clock = _Clock()
    limiter = RateLimiter(RateLimitConfig(rps=1.0, burst=1), clock=clock)
    assert limiter.check("a")[0] is True
    # A different key has its own full bucket.
    assert limiter.check("b")[0] is True
    assert limiter.check("a")[0] is False


def test_disabled_config_always_allows() -> None:
    limiter = RateLimiter(RateLimitConfig.from_env({"TRUSTOPS_API_RATE_LIMIT_RPS": "0"}))
    assert limiter.enabled is False
    assert all(limiter.check("k")[0] for _ in range(50))


def test_lru_eviction_bounds_memory() -> None:
    clock = _Clock()
    limiter = RateLimiter(RateLimitConfig(rps=1.0, burst=1, max_keys=10), clock=clock)
    for i in range(100):
        limiter.check(f"key-{i}")
    assert len(limiter._buckets) <= 10  # asserting the memory bound


def test_from_env_defaults_enabled() -> None:
    cfg = RateLimitConfig.from_env({})
    assert cfg.enabled is True
    assert cfg.rps > 0 and cfg.burst > 0


def test_build_rate_limiter_uses_memory_by_default() -> None:
    from security_lakehouse.auth.rate_limit_redis import build_rate_limiter

    limiter = build_rate_limiter(RateLimitConfig(rps=5.0, burst=5), {})
    assert isinstance(limiter, RateLimiter)


def test_build_rate_limiter_selects_redis_when_url_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    from security_lakehouse.auth.rate_limit import ENV_REDIS_URL
    from security_lakehouse.auth.rate_limit_redis import build_rate_limiter

    created: list[str] = []

    class _StubRedisLimiter:
        def __init__(self, config, redis_url, **kwargs) -> None:
            created.append(redis_url)

        @property
        def enabled(self) -> bool:
            return True

        def check(self, key: str) -> tuple[bool, float]:
            return True, 0.0

    monkeypatch.setattr(
        "security_lakehouse.auth.rate_limit_redis.RedisRateLimiter",
        _StubRedisLimiter,
    )
    env = {ENV_REDIS_URL: "redis://redis:6379/0"}
    limiter = build_rate_limiter(RateLimitConfig(rps=5.0, burst=5), env)
    assert isinstance(limiter, _StubRedisLimiter)
    assert created == ["redis://redis:6379/0"]


# --- middleware integration --------------------------------------------------


@pytest.fixture
def frozen_clock() -> _Clock:
    return _Clock()


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, frozen_clock: _Clock):
    # A tiny limit so a couple of requests trip it.
    monkeypatch.setenv("TRUSTOPS_API_RATE_LIMIT_RPS", "1")
    monkeypatch.setenv("TRUSTOPS_API_RATE_LIMIT_BURST", "2")
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    # Time only moves when a test advances it, so a slow run cannot refill the
    # bucket between requests and admit one that should be throttled.
    assert isinstance(app.state.rate_limiter, RateLimiter)
    assert app.state.rate_limiter.config == RateLimitConfig.from_env(dict(os.environ))
    app.state.rate_limiter = RateLimiter(app.state.rate_limiter.config, clock=frozen_clock)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        user = create_user(session, tenant_id=tenant.id, email="dev@acme.test", role="contributor")
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
    return TestClient(app), token


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_api_returns_429_with_retry_after_when_over_limit(client) -> None:
    test_client, token = client
    statuses = [test_client.get("/api/v1/risks", headers=_bearer(token)).status_code for _ in range(5)]
    assert statuses[0] == HTTPStatus.OK
    assert HTTPStatus.TOO_MANY_REQUESTS in statuses

    throttled = test_client.get("/api/v1/risks", headers=_bearer(token))
    assert throttled.status_code == HTTPStatus.TOO_MANY_REQUESTS
    assert int(throttled.headers["Retry-After"]) >= 1
    assert throttled.json()["errors"][0]["code"] == "rate_limited"


def test_throttled_credential_recovers_only_when_the_clock_advances(client, frozen_clock: _Clock) -> None:
    test_client, token = client
    for _ in range(3):
        test_client.get("/api/v1/risks", headers=_bearer(token))
    assert test_client.get("/api/v1/risks", headers=_bearer(token)).status_code == HTTPStatus.TOO_MANY_REQUESTS
    # Wall-clock time spent on a slow machine must not refill the bucket.
    assert test_client.get("/api/v1/risks", headers=_bearer(token)).status_code == HTTPStatus.TOO_MANY_REQUESTS
    frozen_clock.advance(1.0)  # rps=1 -> one token
    assert test_client.get("/api/v1/risks", headers=_bearer(token)).status_code == HTTPStatus.OK
    assert test_client.get("/api/v1/risks", headers=_bearer(token)).status_code == HTTPStatus.TOO_MANY_REQUESTS


def test_health_probe_is_never_throttled(client) -> None:
    test_client, _token = client
    # Far more than the burst; health must always answer for orchestrators.
    assert all(test_client.get("/api/healthz").status_code == HTTPStatus.OK for _ in range(20))


def test_distinct_credentials_do_not_share_a_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_API_RATE_LIMIT_RPS", "0.001")
    monkeypatch.setenv("TRUSTOPS_API_RATE_LIMIT_BURST", "2")
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    tokens = []
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        for i in range(2):
            user = create_user(session, tenant_id=tenant.id, email=f"u{i}@acme.test", role="contributor")
            _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
            tokens.append(token)
    test_client = TestClient(app)
    # A credential is budgeted on its own only once it has authenticated; its
    # first request is charged to the client address like any unknown caller.
    assert test_client.get("/api/v1/risks", headers=_bearer(tokens[0])).status_code == HTTPStatus.OK
    assert test_client.get("/api/v1/risks", headers=_bearer(tokens[1])).status_code == HTTPStatus.OK
    for _ in range(2):
        assert test_client.get("/api/v1/risks", headers=_bearer(tokens[0])).status_code == HTTPStatus.OK
    assert test_client.get("/api/v1/risks", headers=_bearer(tokens[0])).status_code == HTTPStatus.TOO_MANY_REQUESTS
    assert test_client.get("/api/v1/risks", headers=_bearer(tokens[1])).status_code == HTTPStatus.OK


def test_random_bearer_tokens_cannot_mint_fresh_budgets(client) -> None:
    """An unauthenticated token is not a credential: rotating garbage tokens
    must share the caller's address budget instead of opening a new bucket each."""
    import secrets

    test_client, _token = client
    statuses = [test_client.get("/api/v1/risks", headers=_bearer(secrets.token_hex(16))).status_code for _ in range(6)]
    assert HTTPStatus.TOO_MANY_REQUESTS in statuses
    assert statuses[-1] == HTTPStatus.TOO_MANY_REQUESTS


def test_only_authenticated_credentials_get_their_own_bucket(client) -> None:
    from security_lakehouse.server_app import _rate_limit_key

    test_client, token = client
    assert test_client.get("/api/v1/risks", headers=_bearer(token)).status_code == HTTPStatus.OK
    app = test_client.app
    request = type("R", (), {"headers": _bearer(token), "client": type("C", (), {"host": "10.0.0.9"})()})()
    assert _rate_limit_key(request, app.state.rate_limit_known_credentials).startswith("k:")
    assert (
        _rate_limit_key(
            type("R", (), {"headers": _bearer("forged"), "client": request.client})(),
            app.state.rate_limit_known_credentials,
        )
        == "h:10.0.0.9"
    )
