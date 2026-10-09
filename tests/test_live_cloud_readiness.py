"""Live-cloud readiness: probe parity, partial collection, actionable errors."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import security_lakehouse.connector_runner as connector_runner
from security_lakehouse.connector_errors import (
    CollectionGapError,
    ConnectorAccessError,
    ConnectorConfigError,
    collection_gaps,
)
from security_lakehouse.connector_ids import stable_id_slug
from security_lakehouse.connector_state import (
    _safe_run_error,
    append_config_event,
    append_run_event,
    latest_run,
    run_probe,
)
from security_lakehouse.connectors_aws import collect_aws_inventory_evidence, probe_aws_access
from security_lakehouse.connectors_azure import probe_azure_access
from security_lakehouse.connectors_gcp import (
    GCPClient,
    GCPFixtureClient,
    collect_gcp_evidence,
    probe_gcp_access,
)
from security_lakehouse.io import read_jsonl
from security_lakehouse.validation import validate_raw_events

ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"
PROJECT = "acme-prod"
SUBSCRIPTION = "11111111-1111-1111-1111-111111111111"
NOW = datetime(2026, 9, 27, tzinfo=UTC)
GCP_FIXTURE = Path(__file__).parent / "fixtures" / "gcp"


# --- operator-facing errors -------------------------------------------------


def test_operator_errors_surface_their_message_but_sdk_errors_stay_hidden() -> None:
    assert _safe_run_error(ConnectorConfigError("AWS probe requires account_id")) == "AWS probe requires account_id"
    assert (
        _safe_run_error(ConnectorAccessError("permission orgpolicy.policies.list denied on project acme-prod"))
        == "permission orgpolicy.policies.list denied on project acme-prod"
    )
    assert _safe_run_error(ValueError("secret-ish provider text")) == "ValueError"
    assert _safe_run_error(RuntimeError("token=abc")) == "RuntimeError"


def test_operator_errors_keep_value_and_runtime_error_compatibility() -> None:
    assert isinstance(ConnectorConfigError("x"), ValueError)
    assert isinstance(ConnectorAccessError("x"), RuntimeError)


def test_operator_error_message_survives_run_persistence(tmp_path: Path) -> None:
    message = "Org Policy API (orgpolicy.googleapis.com) is not enabled on project acme-prod"
    rec = append_run_event(
        tmp_path,
        connector_id="gcp-posture",
        kind="sync",
        result="error",
        error=_safe_run_error(ConnectorAccessError(message)),
    )
    assert rec["error"] == message


# --- AWS probe / sync credential-mode parity --------------------------------


class _FakeAWSClient:
    instances: list[dict[str, Any]] = []
    account = ACCOUNT

    def __init__(self, **kwargs: Any) -> None:
        type(self).instances.append(kwargs)

    def caller_identity(self) -> dict[str, str]:
        return {"Account": type(self).account, "Arn": "arn:aws:sts::x:assumed-role/r/s", "UserId": "AIDA"}

    def users(self) -> list[dict[str, str]]:
        return [{"UserName": "one"}]


@pytest.fixture
def fake_aws(monkeypatch: pytest.MonkeyPatch) -> type[_FakeAWSClient]:
    _FakeAWSClient.instances = []
    _FakeAWSClient.account = ACCOUNT
    monkeypatch.setattr("security_lakehouse.connectors_aws.AWSClient", _FakeAWSClient)
    return _FakeAWSClient


def test_aws_probe_supports_local_credential_chain_when_allowed(fake_aws: type[_FakeAWSClient]) -> None:
    result = probe_aws_access(
        credentials={"account_id": ACCOUNT},
        options={"region": "us-east-1"},
        allow_ambient_credentials=True,
    )
    assert fake_aws.instances == [{"region_name": "us-east-1", "role_arn": None, "external_id": None}]
    assert result["credential_mode"] == "local_credential_chain"
    assert result["capabilities"] == ["sts:GetCallerIdentity", "iam:ListUsers"]
    assert result["account_id"] == ACCOUNT
    assert result["principal_count"] == 1


def test_aws_probe_without_role_arn_is_rejected_outside_local_cli(fake_aws: type[_FakeAWSClient]) -> None:
    with pytest.raises(ConnectorConfigError, match="role_arn"):
        probe_aws_access(credentials={"account_id": ACCOUNT}, options={})
    assert fake_aws.instances == []


def test_aws_probe_requires_account_id(fake_aws: type[_FakeAWSClient]) -> None:
    with pytest.raises(ConnectorConfigError, match="account_id"):
        probe_aws_access(credentials={}, options={}, allow_ambient_credentials=True)


def test_aws_probe_fails_clearly_on_account_mismatch(fake_aws: type[_FakeAWSClient]) -> None:
    fake_aws.account = OTHER_ACCOUNT
    with pytest.raises(ConnectorAccessError) as caught:
        probe_aws_access(credentials={"account_id": ACCOUNT}, options={}, allow_ambient_credentials=True)
    assert OTHER_ACCOUNT in str(caught.value)
    assert ACCOUNT in str(caught.value)


def test_aws_assume_role_probe_also_verifies_account(fake_aws: type[_FakeAWSClient]) -> None:
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/GrcLakePostureReadOnlyRole"
    result = probe_aws_access(
        credentials={"account_id": ACCOUNT, "role_arn": role_arn, "external_id": "ext"},
        options={},
    )
    assert result["credential_mode"] == "assume_role"
    assert result["capabilities"] == ["sts:AssumeRole", "sts:GetCallerIdentity", "iam:ListUsers"]
    fake_aws.account = OTHER_ACCOUNT
    with pytest.raises(ConnectorAccessError, match="configured for account"):
        probe_aws_access(credentials={"account_id": ACCOUNT, "role_arn": role_arn}, options={})


def test_run_probe_api_default_keeps_role_arn_requirement(tmp_path: Path, fake_aws: type[_FakeAWSClient]) -> None:
    rec = run_probe(tmp_path, connector_id="aws-posture", credentials={"account_id": ACCOUNT}, options={})
    assert rec["result"] == "error"
    assert "role_arn" in rec["error"]
    assert fake_aws.instances == []


def test_cli_probe_then_configure_enables_local_profile_path(
    tmp_path: Path, fake_aws: type[_FakeAWSClient], capsys: pytest.CaptureFixture[str]
) -> None:
    from security_lakehouse.cli import _connectors_configure, _connectors_probe

    creds = json.dumps({"account_id": ACCOUNT})
    probe_args = argparse.Namespace(
        lake=str(tmp_path), connector_id="aws-posture", actor="cli", credentials_json=creds, options_json=None
    )
    assert _connectors_probe(probe_args) == 0
    probe = latest_run(tmp_path, "aws-posture", kind="probe")
    assert probe is not None
    assert probe["result"] == "ok"
    assert probe["metadata"]["credential_mode"] == "local_credential_chain"

    configure_args = argparse.Namespace(
        lake=str(tmp_path),
        connector_id="aws-posture",
        actor="cli",
        state="enabled",
        credentials_json=creds,
        options_json=None,
        sync_schedule=None,
        eval_schedule=None,
        repo=None,
        fixture_dir=None,
        token_env=None,
        no_materialize=False,
    )
    assert _connectors_configure(configure_args) == 0
    capsys.readouterr()


def test_aws_sync_rejects_credentials_for_another_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_aws: type[_FakeAWSClient]
) -> None:
    monkeypatch.delenv("AWS_ACCOUNT_ID", raising=False)
    monkeypatch.delenv("AWS_ROLE_ARN", raising=False)
    monkeypatch.setattr(connector_runner, "AWSClient", _FakeAWSClient)
    fake_aws.account = OTHER_ACCOUNT
    append_config_event(
        tmp_path, connector_id="aws-posture", state="enabled", actor="a", credentials={"account_id": ACCOUNT}
    )
    with pytest.raises(connector_runner.ConnectorSyncError):
        connector_runner.run_connector_sync(tmp_path, connector_id="aws-posture", materialize=False)
    run = latest_run(tmp_path, "aws-posture", kind="sync")
    assert run is not None
    assert "configured for account" in str(run["error"])


def test_aws_inventory_failures_become_coverage_gaps() -> None:
    class ClientError(Exception):
        response = {"Error": {"Code": "AccessDeniedException", "Message": "raw provider detail"}}

    class InventoryClient:
        def inventory(self, service: str, *, region_name: str) -> list[dict]:
            if service == "rds":
                raise ClientError("raw provider detail")
            return [{"id": "i-1"}]

    rows = collect_aws_inventory_evidence(
        InventoryClient(), account_id=ACCOUNT, regions=["us-east-1"], services=["ec2", "rds"], collected_at=NOW
    )
    assert validate_raw_events(rows) == []
    gaps = collection_gaps(rows)
    assert len(gaps) == 1
    assert gaps[0]["collection"] == "inventory:rds:us-east-1"
    assert gaps[0]["reason"] == "permission_denied"
    assert "AccessDeniedException" in gaps[0]["message"]
    assert "raw provider detail" not in json.dumps(rows)
    gap_row = next(r for r in rows if r["attributes"].get("collection_gap"))
    assert gap_row["controls"] == []


# --- GCP graceful degradation -----------------------------------------------


class _GoogleError(Exception):
    """Duck-typed stand-in for google.api_core.exceptions.GoogleAPICallError."""

    def __init__(self, message: str, *, code: int = 403, reason: str | None = None, metadata: dict | None = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.reason = reason
        self.metadata = metadata or {}


class PermissionDenied(_GoogleError):
    pass


def _service_disabled(service: str) -> PermissionDenied:
    return PermissionDenied(
        f"{service} has not been used in project 123 before or it is disabled. token=ya29.secret",
        reason="SERVICE_DISABLED",
        metadata={"service": service, "consumer": "projects/123"},
    )


def _live_gcp_client(*, iam: Any = None, org: Any = None, assets: Any = None) -> GCPClient:
    class Projects:
        def get_iam_policy(self, **_kwargs: Any) -> Any:
            if isinstance(iam, Exception):
                raise iam
            binding = type("B", (), {"role": "roles/viewer", "members": ["user:a@example.com"]})()
            return type("P", (), {"bindings": [binding]})()

    class OrgPolicies:
        def list_policies(self, **_kwargs: Any) -> list[Any]:
            if isinstance(org, Exception):
                raise org
            return []

    class Assets:
        def list_assets(self, **_kwargs: Any) -> list[Any]:
            if isinstance(assets, Exception):
                raise assets
            return [type("A", (), {"name": "//storage.googleapis.com/b1", "asset_type": "storage.Bucket"})()]

    client = object.__new__(GCPClient)
    client.project_id = PROJECT
    client._projects = Projects()
    client._org_policies = OrgPolicies()
    client._assets = Assets()
    return client


def test_gcp_disabled_org_policy_api_is_a_coverage_gap_not_a_failed_sync() -> None:
    client = _live_gcp_client(org=_service_disabled("orgpolicy.googleapis.com"))
    rows = collect_gcp_evidence(client, collected_at=NOW)

    assert validate_raw_events(rows) == []
    assert {r["event_type"] for r in rows} == {"gcp.cloud.iam_binding", "gcp.cloud.asset", "gcp.collection_gap"}
    gaps = collection_gaps(rows)
    assert gaps == [
        {
            "source": "gcp",
            "collection": "org_policies",
            "reason": "api_disabled",
            "api": "orgpolicy.googleapis.com",
            "permission": None,
            "message": (
                "Org Policy API (orgpolicy.googleapis.com) is not enabled on project acme-prod; "
                "organization policies were not collected"
            ),
        }
    ]
    assert "ya29" not in json.dumps(rows)


def test_gcp_permission_denied_names_the_missing_permission() -> None:
    denied = PermissionDenied(
        "Permission 'cloudasset.assets.listResource' denied on resource (or it may not exist).",
        reason="IAM_PERMISSION_DENIED",
        metadata={"permission": "cloudasset.assets.listResource"},
    )
    rows = collect_gcp_evidence(_live_gcp_client(assets=denied), collected_at=NOW)
    gaps = collection_gaps(rows)
    assert len(gaps) == 1
    assert gaps[0]["reason"] == "permission_denied"
    assert gaps[0]["permission"] == "cloudasset.assets.listResource"
    assert gaps[0]["message"] == (
        "permission cloudasset.assets.listResource denied on project acme-prod; asset inventory was not collected"
    )


def test_gcp_classifies_real_google_api_core_service_disabled_error() -> None:
    exceptions = pytest.importorskip("google.api_core.exceptions")
    error_details = pytest.importorskip("google.rpc.error_details_pb2")
    info = error_details.ErrorInfo(
        reason="SERVICE_DISABLED",
        domain="googleapis.com",
        metadata={"service": "cloudasset.googleapis.com", "consumer": "projects/123"},
    )
    real = exceptions.PermissionDenied("Cloud Asset API has not been used in project 123", error_info=info)
    gaps = collection_gaps(collect_gcp_evidence(_live_gcp_client(assets=real), collected_at=NOW))
    assert gaps[0]["reason"] == "api_disabled"
    assert gaps[0]["api"] == "cloudasset.googleapis.com"
    assert gaps[0]["message"].startswith(
        "Cloud Asset API (cloudasset.googleapis.com) is not enabled on project acme-prod"
    )


def test_gcp_permission_denied_without_metadata_falls_back_to_documented_permission() -> None:
    rows = collect_gcp_evidence(_live_gcp_client(org=PermissionDenied("denied")), collected_at=NOW)
    assert collection_gaps(rows)[0]["permission"] == "orgpolicy.policies.list"


def test_gcp_unclassified_failure_still_fails_closed_without_provider_text() -> None:
    boom = _GoogleError("backend exploded token=ya29.secret", code=500)
    with pytest.raises(ConnectorAccessError, match="organization policy read failed") as caught:
        collect_gcp_evidence(_live_gcp_client(org=boom), collected_at=NOW)
    assert "ya29" not in str(caught.value)


def test_gcp_all_collections_unavailable_is_an_error_naming_every_gap() -> None:
    client = _live_gcp_client(
        iam=_service_disabled("cloudresourcemanager.googleapis.com"),
        org=_service_disabled("orgpolicy.googleapis.com"),
        assets=_service_disabled("cloudasset.googleapis.com"),
    )
    with pytest.raises(ConnectorAccessError) as caught:
        collect_gcp_evidence(client, collected_at=NOW)
    text = str(caught.value)
    for api in ("cloudresourcemanager.googleapis.com", "orgpolicy.googleapis.com", "cloudasset.googleapis.com"):
        assert api in text


def test_gcp_missing_org_policy_library_is_a_gap() -> None:
    client = _live_gcp_client()
    client._org_policies = None
    gaps = collection_gaps(collect_gcp_evidence(client, collected_at=NOW))
    assert gaps[0]["reason"] == "client_unavailable"
    assert "google-cloud-org-policy" in gaps[0]["message"]


def test_gcp_sync_with_gaps_is_ok_and_reports_gaps_in_run_and_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GCP_PROJECT_ID", raising=False)
    client = _live_gcp_client(org=_service_disabled("orgpolicy.googleapis.com"))
    monkeypatch.setattr(connector_runner, "GCPClient", lambda project_id: client)
    append_config_event(
        tmp_path, connector_id="gcp-posture", state="enabled", actor="a", credentials={"project_id": PROJECT}
    )
    result = connector_runner.run_connector_sync(tmp_path, connector_id="gcp-posture", materialize=False)

    assert result.result == "ok"
    assert [gap["collection"] for gap in result.coverage_gaps] == ["org_policies"]
    run = latest_run(tmp_path, "gcp-posture", kind="sync")
    assert run is not None
    assert run["result"] == "ok"
    assert run["metadata"]["partial"] is True
    assert run["metadata"]["coverage_gaps"][0]["api"] == "orgpolicy.googleapis.com"


def test_collection_gap_error_carries_structured_fields() -> None:
    gap = CollectionGapError("m", collection="assets", reason="api_disabled", api="cloudasset.googleapis.com")
    assert isinstance(gap, ConnectorAccessError)
    assert gap.attributes() == {
        "collection_gap": True,
        "collection": "assets",
        "reason": "api_disabled",
        "api": "cloudasset.googleapis.com",
        "permission": None,
        "message": "m",
    }


# --- GCP / Azure live probes ------------------------------------------------


def test_gcp_probe_reads_project_iam_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("security_lakehouse.connectors_gcp.GCPClient", lambda project_id: _live_gcp_client())
    result = probe_gcp_access(credentials={"project_id": PROJECT}, options={})
    assert result["ok"] is True
    assert result["project_id"] == PROJECT
    assert result["capabilities"] == ["resourcemanager.projects.getIamPolicy"]
    assert result["binding_count"] == 1


def test_gcp_probe_reports_actionable_access_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _live_gcp_client(iam=_service_disabled("cloudresourcemanager.googleapis.com"))
    monkeypatch.setattr("security_lakehouse.connectors_gcp.GCPClient", lambda project_id: client)
    with pytest.raises(ConnectorAccessError, match=r"cloudresourcemanager\.googleapis\.com"):
        probe_gcp_access(credentials={"project_id": PROJECT}, options={})


def test_gcp_probe_requires_project_id() -> None:
    with pytest.raises(ConnectorConfigError, match="project_id"):
        probe_gcp_access(credentials={}, options={})


def test_gcp_probe_missing_adc_is_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    class DefaultCredentialsError(Exception):
        pass

    def no_adc(project_id: str) -> Any:
        raise DefaultCredentialsError("Your default credentials were not found. See https://x/y")

    monkeypatch.setattr("security_lakehouse.connectors_gcp.GCPClient", no_adc)
    with pytest.raises(ConnectorAccessError, match="Application Default Credentials"):
        probe_gcp_access(credentials={"project_id": PROJECT}, options={})


def test_run_probe_gcp_is_live(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("security_lakehouse.connectors_gcp.GCPClient", lambda project_id: _live_gcp_client())
    rec = run_probe(tmp_path, connector_id="gcp-posture", credentials={"project_id": PROJECT}, options={})
    assert rec["result"] == "ok"
    assert rec["metadata"]["probe_mode"] == "live"

    client = _live_gcp_client(iam=_service_disabled("cloudresourcemanager.googleapis.com"))
    monkeypatch.setattr("security_lakehouse.connectors_gcp.GCPClient", lambda project_id: client)
    rec = run_probe(tmp_path, connector_id="gcp-posture", credentials={"project_id": PROJECT}, options={})
    assert rec["result"] == "error"
    assert "Cloud Resource Manager API (cloudresourcemanager.googleapis.com) is not enabled" in rec["error"]


class _FakeAzureClient:
    def __init__(self, subscription_id: str) -> None:
        self.subscription_id = subscription_id

    def subscription(self) -> dict[str, str]:
        return {"subscriptionId": self.subscription_id, "displayName": "Prod", "state": "Enabled"}


def test_azure_probe_reads_subscription(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("security_lakehouse.connectors_azure.AzureClient", _FakeAzureClient)
    result = probe_azure_access(credentials={"subscription_id": SUBSCRIPTION}, options={})
    assert result == {
        "ok": True,
        "subscription_id": SUBSCRIPTION,
        "subscription_state": "Enabled",
        "capabilities": ["Microsoft.Resources/subscriptions/read"],
    }


def test_azure_probe_falls_back_to_az_cli_when_sdk_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_sdk(subscription_id: str) -> Any:
        raise ConnectorConfigError("azure sdk missing")

    monkeypatch.setattr("security_lakehouse.connectors_azure.AzureClient", no_sdk)
    monkeypatch.setattr("security_lakehouse.connectors_azure.AzureCliClient", _FakeAzureClient)
    assert probe_azure_access(credentials={"subscription_id": SUBSCRIPTION}, options={})["ok"] is True


def test_azure_probe_authorization_failure_is_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    class HttpResponseError(Exception):
        status_code = 403
        error = type("E", (), {"code": "AuthorizationFailed"})()

    class Denied(_FakeAzureClient):
        def subscription(self) -> dict[str, str]:
            raise HttpResponseError("raw provider text with token")

    monkeypatch.setattr("security_lakehouse.connectors_azure.AzureClient", Denied)
    with pytest.raises(ConnectorAccessError) as caught:
        probe_azure_access(credentials={"subscription_id": SUBSCRIPTION}, options={})
    assert "AuthorizationFailed" in str(caught.value)
    assert "Reader" in str(caught.value)
    assert "raw provider text" not in str(caught.value)


def test_run_probe_azure_is_live(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("security_lakehouse.connectors_azure.AzureClient", _FakeAzureClient)
    rec = run_probe(tmp_path, connector_id="azure-posture", credentials={"subscription_id": SUBSCRIPTION}, options={})
    assert rec["result"] == "ok"
    assert rec["metadata"]["probe_mode"] == "live"


# --- evidence identity: long names must not collide -------------------------


def test_stable_id_slug_keeps_short_ids_and_disambiguates_long_ones() -> None:
    assert stable_id_slug("Acme:Signal:Key", fallback="x") == "acme:signal:key"
    assert stable_id_slug("", fallback="x") == "x"
    prefix = "p:asset://compute.googleapis.com/projects/acme-prod/zones/us-central1-a/instances/"
    first = stable_id_slug(prefix + "web-frontend-001", fallback="x")
    second = stable_id_slug(prefix + "web-frontend-002", fallback="x")
    assert first != second
    assert len(first) <= 96
    assert stable_id_slug(prefix + "web-frontend-001", fallback="x") == first


def test_gcp_long_asset_names_do_not_collapse_into_one_event(tmp_path: Path) -> None:
    fixture = tmp_path / "gcp"
    fixture.mkdir()
    base = "//compute.googleapis.com/projects/acme-prod/zones/us-central1-a/instances/"
    assets = [{"name": f"{base}web-frontend-{i:03d}", "asset_type": "compute.Instance"} for i in range(25)]
    (fixture / "assets.json").write_text(json.dumps(assets), encoding="utf-8")
    rows = collect_gcp_evidence(GCPFixtureClient(fixture, project_id=PROJECT), collected_at=NOW)
    assert validate_raw_events(rows) == []
    assert len({row["event_id"] for row in rows}) == 25


def test_sync_evidence_count_matches_rows_landed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GCP_PROJECT_ID", raising=False)
    append_config_event(
        tmp_path,
        connector_id="gcp-posture",
        state="enabled",
        actor="a",
        credentials={"project_id": PROJECT},
        options={"fixture_dir": str(GCP_FIXTURE)},
    )
    result = connector_runner.run_connector_sync(tmp_path, connector_id="gcp-posture", materialize=False)
    landed = [r for r in read_jsonl(tmp_path / connector_runner.CONNECTOR_RAW_FILE) if r.get("source") == "gcp"]
    assert result.evidence_count == len(landed)


def test_console_run_log_shows_partial_sync_coverage_gaps() -> None:
    drawer = (Path(__file__).parents[1] / "app/web/src/components/drawers/ConnectorDrawer.tsx").read_text(
        encoding="utf-8"
    )
    assert "function RunCoverageGaps" in drawer
    assert "coverage_gaps" in drawer
    # Rendered in both the setup-tab and connected-tab run logs.
    assert drawer.count("<RunCoverageGaps run=") == 2
