"""Connector sync registry tests.

The registry in ``connector_runner.REGISTRY`` is the single dispatch table for
connector sync collection, and the single source of truth for which connectors
report a real adapter. These tests pin that contract: the registry holds the
real adapters, ``has_adapter`` agrees with the registry, an unknown connector
still raises the documented ValueError, and a fixture sync for each real
connector still flows through the registry path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from security_lakehouse import connector_runner, connector_state
from security_lakehouse.connectors import load_connector_catalog, validate_connector_catalog, validate_connector_row
from security_lakehouse.io import read_jsonl
from security_lakehouse.validation import validate_raw_events

REAL_ADAPTERS = {
    "snowflake-evidence-lake",
    "clickhouse-telemetry-lake",
    "object-storage-evidence",
    "siem-alerts",
    "runtime-gateway",
    "github-security",
    "gitlab-security",
    "okta-identity",
    "okta-system-log",
    "aws-posture",
    "google-workspace-identity",
    "gcp-posture",
    "azure-posture",
    "jira-ticketing",
    "intune-devices",
    "bamboohr-personnel",
    "rippling-personnel",
    "workday-personnel",
    "databricks-evidence-lake",
    "jamf-devices",
    "crowdstrike-falcon",
    "kubernetes-cluster",
    "knowbe4-training",
    "iceberg-parquet-lake",
}
PREVIEW_CONNECTORS = {
    "jamf-devices",
    "crowdstrike-falcon",
    "kubernetes-cluster",
    "knowbe4-training",
    "iceberg-parquet-lake",
}
FIXTURES = Path(__file__).parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[1]


def test_registry_contains_exactly_the_real_adapters() -> None:
    assert set(connector_runner.REGISTRY) == REAL_ADAPTERS
    assert connector_runner.registered_connector_ids() == frozenset(REAL_ADAPTERS)


def test_implemented_adapters_catalog_flags_agree_with_registry() -> None:
    # connector_state deliberately avoids importing connector_runner to prevent
    # an import cycle; this pins the catalog metadata to the runner registry.
    catalog = load_connector_catalog()
    implemented_from_catalog = {
        connector_id for connector_id, definition in catalog.items() if definition.get("is_implemented")
    }
    assert connector_runner.registered_connector_ids() == frozenset(implemented_from_catalog)
    assert frozenset(REAL_ADAPTERS) == connector_state.IMPLEMENTED_ADAPTERS


def test_preview_connectors_are_labelled_preview_until_live_verified() -> None:
    catalog = load_connector_catalog()
    for connector_id in PREVIEW_CONNECTORS:
        assert catalog[connector_id]["release_stage"] == "preview", connector_id
        assert catalog[connector_id]["is_implemented"] is True
    assert {cid for cid, row in catalog.items() if row.get("release_stage") == "preview"} >= PREVIEW_CONNECTORS


def test_catalog_rejects_an_unknown_release_stage() -> None:
    row = {**load_connector_catalog()["jamf-devices"], "release_stage": "beta-ish"}
    assert any("release_stage" in error for error in validate_connector_row("jamf-devices", row))
    assert validate_connector_row("jamf-devices", {**row, "release_stage": "ga"}) == []
    del row["release_stage"]
    assert validate_connector_row("jamf-devices", row) == []


def test_connector_catalog_accepts_scoped_github_administration_read() -> None:
    assert validate_connector_catalog() == []
    permissions = load_connector_catalog()["github-security"]["minimum_permissions"]
    assert "administration:read" in permissions


def test_cloud_connector_credentials_prefer_keyless_or_reference_auth() -> None:
    catalog = load_connector_catalog()
    assert catalog["aws-posture"]["credential_type"] == "aws_sso_or_read_only_role"
    assert catalog["azure-posture"]["credential_type"] == "azure_default_credential_reader"
    assert catalog["clickhouse-telemetry-lake"]["credential_type"] == "scoped_cloud_identity"

    forbidden = ("password", "pat", "personal_access", "root_key", "access_key", "secret_key")
    for connector_id, definition in catalog.items():
        credential_type = str(definition.get("credential_type") or "").lower()
        assert not any(term in credential_type for term in forbidden), (
            f"{connector_id} credential_type should not advertise static secret auth: {credential_type}"
        )


def test_source_connector_guidance_avoids_password_and_pat_paths() -> None:
    checked_paths = [
        REPO_ROOT / "README.md",
        REPO_ROOT / "docs" / "CONNECTORS.md",
        REPO_ROOT / "docs" / "LIVE_CLOUD_POC.md",
        REPO_ROOT / "docs" / "REPO_AUDIT.md",
        REPO_ROOT / "docs" / "REPO_GOVERNANCE_CONNECTOR.md",
        REPO_ROOT / "app" / "web" / "src" / "components" / "drawers" / "ConnectorDrawer.tsx",
    ]
    forbidden = (
        "GITHUB_TOKEN",
        "SNOWFLAKE_PASSWORD",
        "personal access token",
        'name: "password"',
    )
    for path in checked_paths:
        body = path.read_text(encoding="utf-8")
        for needle in forbidden:
            assert needle not in body, f"{needle!r} should not be recommended in {path}"


def test_snowflake_poc_bootstrap_matches_connector_contract() -> None:
    body = (REPO_ROOT / "deploy" / "snowflake" / "bootstrap_poc.sql").read_text(encoding="utf-8")

    for expected in (
        "TRUSTOPS_SECURITY_LAKE",
        "TRUSTOPS_READ_WH",
        "TRUSTOPS_READER",
        "TRUSTOPS_AUDIT_EVENTS",
        "TRUSTOPS_CONTROL_POSTURE",
        "TRUSTOPS_ASSET_RISK",
        "TRUSTOPS_EVIDENCE_BUNDLES",
    ):
        assert expected in body
    assert "GRANT SELECT ON VIEW" in body
    assert "GRANT USAGE ON WAREHOUSE TRUSTOPS_READ_WH" in body
    assert "CREATE USER" not in body
    assert "PASSWORD" not in body
    assert "SECRET" not in body


def test_aws_posture_role_bootstrap_matches_connector_contract() -> None:
    body = (REPO_ROOT / "deploy" / "aws" / "trustops-posture-readonly-role.yaml").read_text(encoding="utf-8")

    for expected in (
        "TrustOpsPostureReadOnlyRole",
        "sts:AssumeRole",
        "sts:ExternalId",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:GetLoginProfile",
        "iam:ListAccessKeys",
        "iam:ListMFADevices",
        "iam:ListUsers",
    ):
        assert expected in body

    for forbidden in (
        "iam:Create",
        "iam:Delete",
        "iam:Update",
        "iam:Put",
        "iam:Attach",
        "iam:Detach",
        "iam:PassRole",
        "AdministratorAccess",
        "PowerUserAccess",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
    ):
        assert forbidden not in body

    assert 'Default: ""' not in body
    assert "NoEcho: true" in body
    assert "CREATE USER" not in body.upper()


def test_aws_assume_role_lifecycle_is_documented_for_operators() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs" / "LIVE_CLOUD_POC.md").read_text(encoding="utf-8")
    deploy_readme = (REPO_ROOT / "deploy" / "README.md").read_text(encoding="utf-8")
    connectors = (REPO_ROOT / "docs" / "CONNECTORS.md").read_text(encoding="utf-8")
    visual = (REPO_ROOT / "docs" / "images" / "trustops-aws-sts-lifecycle.svg").read_text(encoding="utf-8")
    combined = "\n".join([readme, runbook, deploy_readme, connectors, visual])

    for expected in (
        "STS AssumeRole",
        "short-lived session credentials",
        "temporary credentials expire",
        "no long-lived access keys",
        "scheduled sync",
        "read-only IAM posture APIs",
        "External ID",
        "CloudFormation StackSets",
        "Terraform workspaces",
        "one External ID per deployed role",
        "Bulk account import",
    ):
        assert expected in combined

    assert "trustops-aws-sts-lifecycle.svg" in readme


def test_azure_posture_reader_bootstrap_matches_connector_contract() -> None:
    body = (REPO_ROOT / "deploy" / "azure" / "trustops-posture-reader.bicep").read_text(encoding="utf-8")

    assert "targetScope = 'subscription'" in body
    assert "Microsoft.Authorization/roleAssignments@2022-04-01" in body
    assert "acdd72a7-3385-48ef-bd42-f606fba81ae7" in body
    assert "DefaultAzureCredential" not in body

    for forbidden in (
        "Owner",
        "Contributor",
        "User Access Administrator",
        "Managed Identity Operator",
        "f1a07417-d97a-45cb-824c-7a7467783830",
        "password",
        "clientSecret",
        "accessKey",
    ):
        assert forbidden not in body


def test_has_adapter_agrees_with_registry() -> None:
    for connector_id in REAL_ADAPTERS:
        assert connector_state.has_adapter(connector_id) is True
    # A catalog connector without a registered builder is contract-only.
    assert connector_state.has_adapter("identity-provider") is False
    assert connector_state.has_adapter("not-a-real-connector") is False


def test_unknown_connector_id_raises_no_runner_registered(tmp_path: Path) -> None:
    connector_state.append_config_event(
        tmp_path,
        connector_id="identity-provider",
        state="enabled",
        actor="alice",
    )
    with pytest.raises(connector_runner.ConnectorSyncError, match="no sync runner registered") as exc:
        connector_runner.run_connector_sync(tmp_path, connector_id="identity-provider")
    assert exc.value.run["result"] == "error"


@pytest.mark.parametrize(
    ("connector_id", "fixture", "extra"),
    [
        ("github-security", "github-governance", {"repo": "acme/model-service"}),
        ("gitlab-security", "gitlab-governance", {"repo": "acme/private-agent-api"}),
        ("snowflake-evidence-lake", "snowflake", {}),
        ("clickhouse-telemetry-lake", "clickhouse-telemetry-lake", {}),
        ("object-storage-evidence", "object-storage-evidence", {}),
        ("siem-alerts", "siem-alerts", {}),
        ("runtime-gateway", "runtime-gateway", {}),
        ("okta-identity", "okta", {}),
        ("aws-posture", "aws", {}),
        ("google-workspace-identity", "google_workspace", {}),
        ("gcp-posture", "gcp", {}),
        ("azure-posture", "azure", {}),
        ("jira-ticketing", "jira", {}),
        ("intune-devices", "intune", {}),
        ("bamboohr-personnel", "bamboohr", {}),
        ("jamf-devices", "jamf", {}),
        ("crowdstrike-falcon", "crowdstrike", {}),
        ("kubernetes-cluster", "kubernetes", {}),
        ("knowbe4-training", "knowbe4", {}),
    ],
)
def test_fixture_sync_flows_through_registry(
    tmp_path: Path,
    connector_id: str,
    fixture: str,
    extra: dict[str, str],
) -> None:
    connector_state.append_config_event(tmp_path, connector_id=connector_id, state="enabled", actor="alice")
    result = connector_runner.run_connector_sync(
        tmp_path,
        connector_id=connector_id,
        fixture_dir=FIXTURES / fixture,
        **extra,
    )
    assert result.result == "ok"
    assert result.evidence_count > 0
    assert result.materialized is True

    raw_rows = read_jsonl(tmp_path / connector_runner.CONNECTOR_RAW_FILE)
    assert validate_raw_events(raw_rows) == []
    assert len(raw_rows) == result.evidence_count

    run = connector_state.latest_run(tmp_path, connector_id, kind="sync")
    assert run["result"] == "ok"
    assert run["evidence_count"] == result.evidence_count
