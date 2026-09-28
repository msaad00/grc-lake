from __future__ import annotations

import threading

import pytest

from security_lakehouse.execution_mode import (
    COMMERCIAL_HOSTED_ENV,
    in_server_mode,
    run_in_server_mode,
    server_execution,
    server_tenant_id,
)


@pytest.fixture(autouse=True)
def _no_hosted_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(COMMERCIAL_HOSTED_ENV, raising=False)


def test_local_by_default() -> None:
    assert in_server_mode() is False
    assert server_tenant_id() is None


def test_server_execution_scopes_the_flag_and_tenant() -> None:
    with server_execution("tenant-a"):
        assert in_server_mode() is True
        assert server_tenant_id() == "tenant-a"
    assert in_server_mode() is False
    assert server_tenant_id() is None


def test_run_in_server_mode_sets_flag_inside_worker_thread() -> None:
    seen: dict[str, object] = {}

    def probe() -> None:
        seen["mode"] = run_in_server_mode("t1", lambda: (in_server_mode(), server_tenant_id()))

    thread = threading.Thread(target=probe)
    thread.start()
    thread.join()
    assert seen["mode"] == (True, "t1")
    assert in_server_mode() is False


def test_hosted_flag_forces_server_mode_without_request_context() -> None:
    assert in_server_mode({COMMERCIAL_HOSTED_ENV: "1"}) is True
    assert in_server_mode({COMMERCIAL_HOSTED_ENV: "0"}) is False


def test_tenant_is_derived_from_tenant_lake_path_when_no_context(tmp_path) -> None:
    assert server_tenant_id(tmp_path / "root" / "tenants" / "abc-123") == "abc-123"
    assert server_tenant_id(tmp_path / "flat") is None
    with server_execution("ctx"):
        assert server_tenant_id(tmp_path / "root" / "tenants" / "abc-123") == "ctx"
