"""Workflow ``{{secret.NAME}}`` tokens resolve per tenant in hosted server mode."""

from __future__ import annotations

import base64
import json
import urllib.request
from pathlib import Path

import pytest

import security_lakehouse.workflows as wf
from security_lakehouse import netguard
from security_lakehouse.execution_mode import COMMERCIAL_HOSTED_ENV, server_execution


class _Response:
    status = 200

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self, amt: int | None = None) -> bytes:
        return b"{}"


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> list[urllib.request.Request]:
    sent: list[urllib.request.Request] = []

    def _open(request, timeout=None, validate=None):  # noqa: ANN001, ARG001
        sent.append(request)
        return _Response()

    monkeypatch.setattr(netguard, "open_guarded", _open)
    monkeypatch.setattr(netguard.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    monkeypatch.setattr(wf, "_webhook_backoff_sleep", lambda _s: None)
    monkeypatch.setenv(wf.EGRESS_ALLOWLIST_ENV, "hooks.example.com")
    monkeypatch.delenv(COMMERCIAL_HOSTED_ENV, raising=False)
    monkeypatch.delenv(wf.WORKFLOW_SHARED_SECRETS_ENV, raising=False)
    for name in ("TRUSTOPS_SECRET_FOO", "TRUSTOPS_TENANT_ACME__SECRET_FOO", "TRUSTOPS_TENANT_GLOBEX__SECRET_FOO"):
        monkeypatch.delenv(name, raising=False)
    return sent


def _webhook(lake: Path, token: str = "{{secret.FOO}}") -> dict:
    return wf.run_action(
        lake,
        node_type="action.webhook",
        params={"url": "https://hooks.example.com/x", "headers": {"Authorization": f"Bearer {token}"}},
    )


def test_local_mode_keeps_the_shared_namespace(monkeypatch, tmp_path, captured) -> None:
    monkeypatch.setenv("TRUSTOPS_SECRET_FOO", "local-value")
    _webhook(tmp_path)
    assert captured[0].get_header("Authorization") == "Bearer local-value"


def test_server_mode_resolves_the_tenant_scoped_secret(monkeypatch, tmp_path, captured) -> None:
    monkeypatch.setenv("TRUSTOPS_TENANT_ACME__SECRET_FOO", "acme-value")
    monkeypatch.setenv("TRUSTOPS_SECRET_FOO", "shared-value")
    with server_execution("acme"):
        out = _webhook(tmp_path)
    assert captured[0].get_header("Authorization") == "Bearer acme-value"
    assert "acme-value" not in json.dumps(out)


def test_tenant_cannot_resolve_another_tenants_secret(monkeypatch, tmp_path, captured) -> None:
    monkeypatch.setenv("TRUSTOPS_TENANT_GLOBEX__SECRET_FOO", "globex-value")
    with server_execution("acme"), pytest.raises(ValueError, match="not set for this tenant"):
        _webhook(tmp_path)
    assert captured == []


def test_tenant_cannot_name_another_tenants_prefix_through_the_token(monkeypatch, tmp_path, captured) -> None:
    # The token names only the suffix; the tenant's own prefix is always prepended.
    monkeypatch.setenv("TRUSTOPS_TENANT_GLOBEX__SECRET_FOO", "globex-value")
    monkeypatch.setenv("TRUSTOPS_SECRET_TRUSTOPS_TENANT_GLOBEX__SECRET_FOO", "globex-value")
    with server_execution("acme"), pytest.raises(ValueError):
        _webhook(tmp_path, "{{secret.TRUSTOPS_TENANT_GLOBEX__SECRET_FOO}}")
    assert captured == []


def test_server_mode_refuses_the_shared_namespace(monkeypatch, tmp_path, captured) -> None:
    monkeypatch.setenv("TRUSTOPS_SECRET_FOO", "shared-value")
    with server_execution("acme"), pytest.raises(ValueError, match="not set for this tenant"):
        _webhook(tmp_path)
    assert captured == []


def test_operator_allowlisted_shared_secret_resolves_in_server_mode(monkeypatch, tmp_path, captured) -> None:
    monkeypatch.setenv("TRUSTOPS_SECRET_FOO", "shared-value")
    monkeypatch.setenv(wf.WORKFLOW_SHARED_SECRETS_ENV, "BAR, FOO")
    with server_execution("acme"):
        _webhook(tmp_path)
    assert captured[0].get_header("Authorization") == "Bearer shared-value"


def test_tenant_secret_wins_over_an_allowlisted_shared_one(monkeypatch, tmp_path, captured) -> None:
    monkeypatch.setenv("TRUSTOPS_SECRET_FOO", "shared-value")
    monkeypatch.setenv("TRUSTOPS_TENANT_ACME__SECRET_FOO", "acme-value")
    monkeypatch.setenv(wf.WORKFLOW_SHARED_SECRETS_ENV, "FOO")
    with server_execution("acme"):
        _webhook(tmp_path)
    assert captured[0].get_header("Authorization") == "Bearer acme-value"


def test_server_mode_without_a_tenant_refuses(monkeypatch, tmp_path, captured) -> None:
    monkeypatch.setenv("TRUSTOPS_SECRET_FOO", "shared-value")
    with server_execution(None), pytest.raises(ValueError, match="not set for this tenant"):
        _webhook(tmp_path)
    assert captured == []


def test_hosted_daemon_resolves_the_tenant_from_the_lake_path(monkeypatch, tmp_path, captured) -> None:
    monkeypatch.setenv(COMMERCIAL_HOSTED_ENV, "1")
    monkeypatch.setenv("TRUSTOPS_TENANT_ACME__SECRET_FOO", "acme-value")
    monkeypatch.setenv("TRUSTOPS_TENANT_GLOBEX__SECRET_FOO", "globex-value")
    lake = tmp_path / "tenants" / "acme"
    lake.mkdir(parents=True)
    _webhook(lake)
    assert captured[0].get_header("Authorization") == "Bearer acme-value"


def test_jira_basic_auth_resolves_per_tenant(monkeypatch, tmp_path, captured) -> None:
    monkeypatch.setenv("TRUSTOPS_TENANT_ACME__SECRET_FOO", "acme-token")
    monkeypatch.setenv("TRUSTOPS_TENANT_GLOBEX__SECRET_FOO", "globex-token")
    monkeypatch.setenv(wf.EGRESS_ALLOWLIST_ENV, "acme.atlassian.net")
    with server_execution("acme"):
        wf.run_action(
            tmp_path,
            node_type="action.jira",
            params={
                "base_url": "https://acme.atlassian.net",
                "project_key": "SEC",
                "summary": "s",
                "email": "a@example.com",
                "token": "{{secret.FOO}}",
            },
        )
    expected = "Basic " + base64.b64encode(b"a@example.com:acme-token").decode("ascii")
    assert captured[0].get_header("Authorization") == expected
