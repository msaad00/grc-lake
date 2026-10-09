"""At sync time, a stored ref to a server secret is refused before any egress.

Configure-time validation covers new configs; this covers configs saved before
the policy existed (or written by a non-API path) that a hosted sync replays.
"""

from __future__ import annotations

from typing import Any

import pytest

from security_lakehouse import connector_runner, netguard
from security_lakehouse.connector_runner import DEFAULT_TOKEN_ENV, SyncInputs, effective_registry
from security_lakehouse.execution_mode import COMMERCIAL_HOSTED_ENV, server_execution
from security_lakehouse.secret_refs import SecretRefPolicyError

SERVER_SECRET = "GRC_LAKE_COOKIE_SIGNING_KEY"

# Enough non-secret identity for each live path to reach its secret lookup.
IDENTITY: dict[str, Any] = {
    "base_url": "https://acme.example.com",
    "org_url": "https://acme.okta.com",
    "host": "https://acme.example.com",
    "client_id": "cid",
    "customer_id": "C0123",
    "subdomain": "acme",
    "tenant": "acme",
    "report_url": "https://wd.example.com/ccx/service/customreport2/acme/isu/report",
    "username": "isu",
    "email": "bot@acme.example.com",
    "region": "us",
    "cluster_name": "c",
    "warehouse_id": "w",
    "catalog": "main",
    "schema": "security",
    "account": "acme-xy12345",
    "user": "reader",
}

CASES = {
    "jamf-devices": "client_secret_ref",
    "crowdstrike-falcon": "client_secret_ref",
    "databricks-evidence-lake": "client_secret_ref",
    "bamboohr-personnel": "credential_ref",
    "rippling-personnel": "credential_ref",
    "workday-personnel": "credential_ref",
    "knowbe4-training": "credential_ref",
    "siem-alerts": "credential_ref",
    "runtime-gateway": "credential_ref",
    "clickhouse-telemetry-lake": "credential_ref",
    "okta-identity": "credential_ref",
    "okta-system-log": "credential_ref",
    "jira-ticketing": "credential_ref",
    "google-workspace-identity": "refresh_token_ref",
    "snowflake-evidence-lake": "private_key_ref",
    "kubernetes-cluster": "kubeconfig_ref",
    "github-security": "credential_ref",
    "gitlab-security": "credential_ref",
}


@pytest.fixture(autouse=True)
def _no_egress(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(COMMERCIAL_HOSTED_ENV, raising=False)

    def refuse(*_: Any, **__: Any) -> Any:
        raise AssertionError("network egress attempted before the secret ref was checked")

    monkeypatch.setattr(netguard, "assert_url_is_public", refuse)
    monkeypatch.setattr(netguard, "assert_resolved_ip_is_public", refuse, raising=False)


@pytest.mark.parametrize(("connector_id", "field"), sorted(CASES.items()))
def test_hosted_sync_refuses_a_stored_server_secret_ref(connector_id: str, field: str) -> None:
    builder = effective_registry()[connector_id]
    inputs = SyncInputs(
        repo="acme/app",
        fixture_dir=None,
        token_env=DEFAULT_TOKEN_ENV,
        env={SERVER_SECRET: "server-signing-key"},
        credentials={**IDENTITY, field: SERVER_SECRET},
        options={"repo": "acme/app"},
    )
    with server_execution("tenant-a"), pytest.raises(SecretRefPolicyError):
        builder(inputs)


def test_hosted_sync_derives_tenant_from_lake_path_without_request_context(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from security_lakehouse.execution_mode import server_tenant_id

    seen: dict[str, Any] = {}

    def fake_collect(*_: Any, **__: Any) -> list[dict[str, Any]]:
        seen["tenant"] = server_tenant_id()
        return []

    monkeypatch.setenv(COMMERCIAL_HOSTED_ENV, "1")
    monkeypatch.setattr(connector_runner, "_require_enabled", lambda *_: {"credentials": {}, "options": {}})
    monkeypatch.setattr(connector_runner, "_collect", fake_collect)
    lake = tmp_path / "root" / "tenants" / "tenant-b"
    lake.mkdir(parents=True)
    connector_runner.run_connector_sync(lake, connector_id="siem-alerts", materialize=False)
    assert seen["tenant"] == "tenant-b"
