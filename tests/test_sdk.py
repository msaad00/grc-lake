"""SDK tests: drive ``GrcLakeClient`` against the real app over a live socket.

The SDK is a *synchronous* ``httpx.Client``, so we serve each FastAPI app with
uvicorn on an ephemeral localhost port in a background thread and point the
client at it -- exercising the genuine wire path (sockets + HTTP), not an
in-memory shortcut. Read paths run on an app started with ``require_auth=False``;
the write/round-trip path provisions a tenant + API key and sends a real Bearer
token, proving the SDK contract == the human one.
"""

from __future__ import annotations

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
from security_lakehouse.sdk import GrcLakeClient, GrcLakeError  # noqa: E402
from security_lakehouse.server_app import create_app  # noqa: E402
from test_api_v1 import _seed_lake  # noqa: E402


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextlib.contextmanager
def _client(app, *, api_key: str | None = None) -> Iterator[GrcLakeClient]:
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10.0
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started, "uvicorn did not start"
    client = GrcLakeClient(f"http://127.0.0.1:{port}", api_key=api_key, timeout=10.0)
    try:
        yield client
    finally:
        client.close()
        server.should_exit = True
        thread.join(timeout=10.0)


def _provision(app, slug: str = "acme", role: str = "contributor") -> str:
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug=slug, name=slug.title())
        user = create_user(session, tenant_id=tenant.id, email=f"{role}@{slug}.test", role=role)
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        return token


def test_describe_api_returns_catalog(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    with _client(create_app(tmp_path, require_auth=False)) as client:
        catalog = client.describe_api()
    assert catalog["api_version"] == "v1"
    paths = {row["path"] for row in catalog["resources"]}
    assert "/api/v1/controls" in paths
    assert "/api/v1/risks" in paths


def test_get_posture_has_score(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    with _client(create_app(tmp_path, require_auth=False)) as client:
        posture = client.get_posture()
    assert "score" in posture["posture"]
    assert isinstance(posture["posture"]["score"], int | float)


def test_list_controls_returns_seeded_ids(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    with _client(create_app(tmp_path, require_auth=False)) as client:
        controls = client.list_controls(sort="-risk_score")
    ids = {row["control_id"] for row in controls}
    assert {"SOC2-CC6.1", "NIST-AI-RMF-MAP-1.5"} <= ids


def test_collection_kwargs_map_to_query_params(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    with _client(create_app(tmp_path, require_auth=False)) as client:
        rows = client.list_controls(limit=1, sort="-risk_score")
        filtered = client.list_assets(filter={"asset_type": "model"})
    assert len(rows) == 1
    assert rows[0]["control_id"] == "SOC2-CC6.1"
    assert {row["asset_type"] for row in filtered} == {"model"}


def test_create_snapshot_round_trips(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    with _client(create_app(tmp_path, require_auth=False)) as client:
        created = client.create_snapshot(reason="sdk-test")
        snapshots = client.list_snapshots()
    assert created["reason"] == "sdk-test"
    assert any(row["reason"] == "sdk-test" for row in snapshots)


def test_posture_as_of_round_trips(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    with _client(create_app(tmp_path, require_auth=False)) as client:
        client.create_snapshot(reason="sdk-as-of")
        found = client.posture_as_of("2030-01-01")
        empty = client.posture_as_of("2000-01-01")
    assert found["found"] is True
    assert found["assessment_hash"]
    assert empty["found"] is False


def test_create_risk_then_list_round_trips(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    token = _provision(app)
    with _client(app, api_key=token) as client:
        created = client.create_risk(title="Vendor data exfiltration", severity="high", owner="alice")
        risk_id = created["id"]
        listed = client.list_risks()
        fetched = client.get_risk(risk_id)
        updated = client.update_risk(risk_id, status="mitigating")
        deleted = client.delete_risk(risk_id)
    assert created["title"] == "Vendor data exfiltration"
    assert any(row["id"] == risk_id for row in listed)
    assert fetched["id"] == risk_id
    assert updated["status"] == "mitigating"
    assert deleted["deleted"] is True


def test_create_task_then_list_round_trips(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    token = _provision(app)
    with _client(app, api_key=token) as client:
        created = client.create_task(title="Rotate access keys", owner="bob", priority="high")
        tasks = client.list_tasks()
    assert created["title"] == "Rotate access keys"
    assert any(row["id"] == created["id"] for row in tasks)


def test_non_2xx_raises_typed_error_with_envelope(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    with (
        _client(create_app(tmp_path, require_auth=False)) as client,
        pytest.raises(GrcLakeError) as excinfo,
    ):
        client.list_controls(limit=9999)  # limit > 1000 -> 400 bad_request
    err = excinfo.value
    assert err.status_code == 400
    assert err.errors
    assert err.errors[0]["code"] == "bad_request"


def test_unauthorized_write_raises_typed_error(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    # require_auth on, but no bearer token -> 401 with an error envelope.
    with (
        _client(create_app(tmp_path)) as client,
        pytest.raises(GrcLakeError) as excinfo,
    ):
        client.create_risk(title="x")
    assert excinfo.value.status_code == 401
