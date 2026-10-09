"""Public GRC Lake identity and upgrade-compatible configuration."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from security_lakehouse.runtime_environment import runtime_env


def test_new_environment_names_take_precedence_without_mutating_input() -> None:
    original = {"TRUSTOPS_DATABASE_URL": "sqlite:///old.db", "GRC_LAKE_DATABASE_URL": "sqlite:///new.db"}
    assert runtime_env(original)["GRC_LAKE_DATABASE_URL"] == "sqlite:///new.db"
    assert runtime_env(original)["TRUSTOPS_DATABASE_URL"] == "sqlite:///new.db"
    assert original["TRUSTOPS_DATABASE_URL"] == "sqlite:///old.db"


def test_legacy_environment_and_explicit_empty_values_remain_supported() -> None:
    assert runtime_env({"TRUSTOPS_ENV": "production"})["GRC_LAKE_ENV"] == "production"
    assert runtime_env({"TRUSTOPS_API_KEY": "legacy", "GRC_LAKE_API_KEY": ""})["TRUSTOPS_API_KEY"] == ""
    assert runtime_env({}) == {}


def test_auth_guard_accepts_both_environment_prefixes(monkeypatch: pytest.MonkeyPatch) -> None:
    from security_lakehouse.auth.sessions import cookie_signing_key

    monkeypatch.delenv("GRC_LAKE_COOKIE_SIGNING_KEY", raising=False)
    monkeypatch.setenv("TRUSTOPS_COOKIE_SIGNING_KEY", "old-key")
    assert cookie_signing_key() == "old-key"
    monkeypatch.setenv("GRC_LAKE_COOKIE_SIGNING_KEY", "new-key")
    assert cookie_signing_key() == "new-key"


def test_new_distribution_exposes_new_commands_and_legacy_aliases() -> None:
    project = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())["project"]
    assert project["name"] == "grc-lake"
    assert project["scripts"]["grc-lake"] == project["scripts"]["security-lakehouse"]
    assert project["scripts"]["grc-lake-mcp"] == project["scripts"]["trustops-mcp"]


def test_sdk_retains_existing_imports() -> None:
    from security_lakehouse.sdk import GrcLakeClient, GrcLakeError, TrustOpsClient, TrustOpsError

    assert GrcLakeClient is TrustOpsClient
    assert GrcLakeError is TrustOpsError


def test_legacy_secret_references_keep_tenant_boundaries() -> None:
    from security_lakehouse.execution_mode import server_execution
    from security_lakehouse.secret_refs import resolve_secret_ref, secret_ref_denial

    env = {
        "TRUSTOPS_TENANT_ACME__TOKEN": "tenant-token",
        "TRUSTOPS_TENANT_OTHER__TOKEN": "other-token",
        "TRUSTOPS_COOKIE_SIGNING_KEY": "server-secret",
        "GRC_LAKE_CONNECTOR_SECRET_REFS": "TRUSTOPS_*",
    }
    with server_execution(tenant_id="acme"):
        assert secret_ref_denial("TRUSTOPS_COOKIE_SIGNING_KEY", env=env)
        assert secret_ref_denial("TRUSTOPS_TENANT_OTHER__TOKEN", env=env)
        assert resolve_secret_ref("TRUSTOPS_TENANT_ACME__TOKEN", env) == "tenant-token"
        assert resolve_secret_ref("GRC_LAKE_TENANT_ACME__TOKEN", env) == "tenant-token"
