"""Async SDK tests: drive ``AsyncGrcLakeClient`` against the real app.

Mirrors :mod:`test_sdk` but for the coroutine surface. Each FastAPI app is
served by uvicorn on an ephemeral localhost port in a background thread (the
same live-socket harness the sync tests use), and the async coroutines are
driven with ``asyncio.run`` -- no ``pytest-asyncio`` dependency. Read paths run
on an app started with ``require_auth=False``; the write/round-trip path
provisions a tenant + API key and sends a real Bearer token.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")
pytest.importorskip("uvicorn")

import uvicorn  # noqa: E402

from security_lakehouse.db.base import session_scope  # noqa: E402
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user  # noqa: E402
from security_lakehouse.sdk import AsyncGrcLakeClient, GrcLakeError  # noqa: E402
from security_lakehouse.server_app import create_app  # noqa: E402
from test_api_v1 import _seed_lake  # noqa: E402


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextlib.contextmanager
def _server(app) -> Iterator[str]:
    """Serve ``app`` over a live socket and yield its base URL."""
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10.0
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started, "uvicorn did not start"
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10.0)


def _provision(app, slug: str = "acme", role: str = "contributor") -> str:
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug=slug, name=slug.title())
        user = create_user(session, tenant_id=tenant.id, email=f"{role}@{slug}.test", role=role)
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        return token


def test_async_get_posture_has_score(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    with _server(create_app(tmp_path, require_auth=False)) as base_url:

        async def run() -> dict:
            async with AsyncGrcLakeClient(base_url, timeout=10.0) as client:
                return await client.get_posture()

        posture = asyncio.run(run())
    assert "score" in posture["posture"]
    assert isinstance(posture["posture"]["score"], int | float)


def test_async_posture_as_of_round_trips(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    with _server(create_app(tmp_path, require_auth=False)) as base_url:

        async def run() -> tuple[dict, dict]:
            async with AsyncGrcLakeClient(base_url, timeout=10.0) as client:
                await client.create_snapshot(reason="async-as-of")
                return await client.posture_as_of("2030-01-01"), await client.posture_as_of("2000-01-01")

        found, empty = asyncio.run(run())
    assert found["found"] is True
    assert empty["found"] is False


def test_async_list_controls_returns_seeded_ids(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    with _server(create_app(tmp_path, require_auth=False)) as base_url:

        async def run() -> list[dict]:
            async with AsyncGrcLakeClient(base_url, timeout=10.0) as client:
                return await client.list_controls(sort="-risk_score")

        controls = asyncio.run(run())
    ids = {row["control_id"] for row in controls}
    assert {"SOC2-CC6.1", "NIST-AI-RMF-MAP-1.5"} <= ids


def test_async_create_risk_then_list_round_trips(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    token = _provision(app)
    with _server(app) as base_url:

        async def run() -> tuple[dict, list[dict], dict, dict, dict]:
            async with AsyncGrcLakeClient(base_url, api_key=token, timeout=10.0) as client:
                created = await client.create_risk(title="Vendor data exfiltration", severity="high", owner="alice")
                risk_id = created["id"]
                listed = await client.list_risks()
                fetched = await client.get_risk(risk_id)
                updated = await client.update_risk(risk_id, status="mitigating")
                deleted = await client.delete_risk(risk_id)
                return created, listed, fetched, updated, deleted

        created, listed, fetched, updated, deleted = asyncio.run(run())
    assert created["title"] == "Vendor data exfiltration"
    assert any(row["id"] == created["id"] for row in listed)
    assert fetched["id"] == created["id"]
    assert updated["status"] == "mitigating"
    assert deleted["deleted"] is True


def test_async_create_task_then_list_round_trips(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    token = _provision(app)
    with _server(app) as base_url:

        async def run() -> tuple[dict, list[dict]]:
            async with AsyncGrcLakeClient(base_url, api_key=token, timeout=10.0) as client:
                created = await client.create_task(title="Rotate access keys", owner="bob", priority="high")
                tasks = await client.list_tasks()
                return created, tasks

        created, tasks = asyncio.run(run())
    assert created["title"] == "Rotate access keys"
    assert any(row["id"] == created["id"] for row in tasks)


def test_async_create_snapshot_round_trips(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    with _server(create_app(tmp_path, require_auth=False)) as base_url:

        async def run() -> tuple[dict, list[dict]]:
            async with AsyncGrcLakeClient(base_url, timeout=10.0) as client:
                created = await client.create_snapshot(reason="async-sdk-test")
                snapshots = await client.list_snapshots()
                return created, snapshots

        created, snapshots = asyncio.run(run())
    assert created["reason"] == "async-sdk-test"
    assert any(row["reason"] == "async-sdk-test" for row in snapshots)


def test_async_non_2xx_raises_typed_error_with_envelope(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    with _server(create_app(tmp_path, require_auth=False)) as base_url:

        async def run() -> None:
            async with AsyncGrcLakeClient(base_url, timeout=10.0) as client:
                await client.list_controls(limit=9999)  # limit > 1000 -> 400 bad_request

        with pytest.raises(GrcLakeError) as excinfo:
            asyncio.run(run())
    err = excinfo.value
    assert err.status_code == 400
    assert err.errors
    assert err.errors[0]["code"] == "bad_request"


def test_async_explicit_close_releases_pool(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    with _server(create_app(tmp_path, require_auth=False)) as base_url:

        async def run() -> dict:
            client = AsyncGrcLakeClient(base_url, timeout=10.0)
            try:
                return await client.describe_api()
            finally:
                await client.close()

        catalog = asyncio.run(run())
    assert catalog["api_version"] == "v1"
