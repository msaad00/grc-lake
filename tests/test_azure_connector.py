"""Azure posture-evidence connector runner tests (fixture-backed)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import security_lakehouse.connector_runner as connector_runner
import security_lakehouse.connectors_azure as connectors_azure
from security_lakehouse.connector_state import (
    append_config_event,
    has_adapter,
    latest_run,
    run_probe,
)
from security_lakehouse.connectors_azure import AzureCliClient, AzureClient, AzureFixtureClient, collect_azure_evidence
from security_lakehouse.io import read_jsonl
from security_lakehouse.validation import validate_raw_events

FIXTURE = Path(__file__).parent / "fixtures" / "azure"
SUBSCRIPTION = "11111111-1111-1111-1111-111111111111"


def _by_type(rows: list[dict], event_type: str) -> list[dict]:
    return [r for r in rows if r["event_type"] == event_type]


def _role(rows: list[dict], role_name: str) -> dict:
    matches = [r for r in _by_type(rows, "azure.cloud.role_assignment") if r["attributes"]["role_name"] == role_name]
    assert len(matches) == 1
    return matches[0]


def test_collect_azure_evidence_is_schema_valid_and_mapped() -> None:
    client = AzureFixtureClient(FIXTURE, subscription_id=SUBSCRIPTION)
    rows = collect_azure_evidence(
        client,
        collected_at=datetime(2026, 6, 3, tzinfo=UTC),
    )

    assert validate_raw_events(rows) == []
    # 3 role assignments + 2 policy assignments + 2 resources = 7 events.
    assert len(rows) == 7

    role = _by_type(rows, "azure.cloud.role_assignment")
    policy = _by_type(rows, "azure.cloud.policy_assignment")
    resource = _by_type(rows, "azure.cloud.resource")
    assert len(role) == 3
    assert len(policy) == 2
    assert len(resource) == 2

    # Every emitted event is azure-scoped and maps to a catalog control.
    for row in rows:
        assert row["source"] == "azure"
        assert "SOC2-CC6.1" in row["controls"]
        assert row["entity"]["org"] == SUBSCRIPTION

    # Owner at subscription scope is a high open identity finding for review.
    owner = _role(rows, "Owner")
    assert owner["status"] == "open"
    assert owner["severity"] == "high"
    assert owner["attributes"]["privileged_role"] is True
    assert owner["attributes"]["subscription_scope"] is True
    # principalType "User" => human identity.
    assert owner["attributes"]["identity_type"] == "human"

    # Reader at subscription scope is observed/info (not privileged).
    reader = _role(rows, "Reader")
    assert reader["status"] == "observed"
    assert reader["severity"] == "info"
    assert reader["attributes"]["privileged_role"] is False
    # principalType "ServicePrincipal" => service identity.
    assert reader["attributes"]["identity_type"] == "service"

    # Contributor scoped to a resource group is not a subscription-scope finding.
    contributor = _role(rows, "Contributor")
    assert contributor["status"] == "observed"
    assert contributor["severity"] == "info"
    assert contributor["attributes"]["privileged_role"] is True
    assert contributor["attributes"]["subscription_scope"] is False

    # An enforcing policy is observed; a DoNotEnforce policy is an open finding.
    enforced = [p for p in policy if p["attributes"]["is_enforced"]]
    not_enforced = [p for p in policy if not p["attributes"]["is_enforced"]]
    assert len(enforced) == 1
    assert len(not_enforced) == 1
    assert enforced[0]["status"] == "observed"
    assert enforced[0]["severity"] == "info"
    assert not_enforced[0]["status"] == "open"
    assert not_enforced[0]["severity"] == "medium"
    assert not_enforced[0]["attributes"]["enforcement_mode"] == "DoNotEnforce"

    # Resources are observed inventory and point at the read-only resource id.
    sample = resource[0]
    assert sample["entity"]["asset_type"] == "cloud_resource"
    assert sample["status"] == "observed"
    assert sample["evidence"]["evidence_ref"] == sample["attributes"]["resource_id"]
    assert sample["evidence"]["evidence_ref"].startswith(f"/subscriptions/{SUBSCRIPTION}")


def test_azure_connector_sync_writes_raw_and_materializes_lake(tmp_path: Path) -> None:
    append_config_event(tmp_path, connector_id="azure-posture", state="enabled", actor="alice")
    result = connector_runner.run_connector_sync(
        tmp_path,
        connector_id="azure-posture",
        fixture_dir=FIXTURE,
    )
    assert result.result == "ok"
    assert result.evidence_count == 7
    assert result.materialized is True

    raw_rows = read_jsonl(tmp_path / connector_runner.CONNECTOR_RAW_FILE)
    assert validate_raw_events(raw_rows) == []
    assert len(raw_rows) == 7
    assert all(r["source"] == "azure" for r in raw_rows)
    assert (tmp_path / "bronze" / "raw_events.jsonl").is_file()
    assert (tmp_path / "silver" / "normalized_events.jsonl").is_file()
    assert (tmp_path / "gold" / "current_posture.json").is_file()

    run = latest_run(tmp_path, "azure-posture", kind="sync")
    assert run["result"] == "ok"
    assert run["evidence_count"] == 7


def test_azure_sync_preserves_evidence_refs_and_generic_evidence_types(tmp_path: Path) -> None:
    append_config_event(tmp_path, connector_id="azure-posture", state="enabled", actor="alice")
    connector_runner.run_connector_sync(tmp_path, connector_id="azure-posture", fixture_dir=FIXTURE)

    silver_rows = read_jsonl(tmp_path / "silver" / "normalized_events.jsonl")
    role_rows = [row for row in silver_rows if row["event_type"] == "azure.cloud.role_assignment"]
    assert role_rows
    assert all(row["evidence_ref"].startswith(f"/subscriptions/{SUBSCRIPTION}") for row in role_rows)
    assert all({"cloud.config", "identity.access_review"} <= set(row["evidence_types"]) for row in role_rows)

    control_tests = {row["control_id"]: row for row in read_jsonl(tmp_path / "gold" / "control_tests.jsonl")}
    soc2 = control_tests["SOC2-CC6.1"]
    assert "cloud.config" in soc2["observed_evidence_types"]
    assert "identity.access_review" in soc2["observed_evidence_types"]
    assert "cloud.config" not in soc2["missing_evidence_types"]
    assert "identity.access_review" not in soc2["missing_evidence_types"]

    hipaa = control_tests["HIPAA-164.308(a)(4)"]
    assert hipaa["result"] == "pass"
    assert hipaa["freshness_status"] == "fresh"

    freshness_rows = read_jsonl(tmp_path / "gold" / "evidence_freshness.jsonl")
    assert freshness_rows
    assert {row["connector_id"] for row in freshness_rows} == {"azure-posture"}

    current_posture = json.loads((tmp_path / "gold" / "current_posture.json").read_text(encoding="utf-8"))
    assert current_posture["evidence_freshness"]["sources"][0]["connector_id"] == "azure-posture"

    assets = read_jsonl(tmp_path / "gold" / "asset_risk.jsonl")
    cloud_resource = next(row for row in assets if row["asset_type"] == "cloud_resource")
    assert "SOC2-CC6.1" in cloud_resource["applicable_control_ids"]
    assert "NIST-AI-RMF-MAP-1.5" in cloud_resource["applicable_control_ids"]


def test_azure_connector_sync_falls_back_to_az_cli_when_sdk_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class BrokenAzureClient:
        def __init__(self, subscription_id: str) -> None:
            raise RuntimeError("azure sdk import failed")

    class FixtureBackedAzureCliClient(AzureFixtureClient):
        def __init__(self, subscription_id: str) -> None:
            super().__init__(FIXTURE, subscription_id=subscription_id)

    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUBSCRIPTION)
    monkeypatch.setattr(connectors_azure, "AzureClient", BrokenAzureClient)
    monkeypatch.setattr(connectors_azure, "AzureCliClient", FixtureBackedAzureCliClient)

    append_config_event(tmp_path, connector_id="azure-posture", state="enabled", actor="a")
    result = connector_runner.run_connector_sync(tmp_path, connector_id="azure-posture")

    assert result.result == "ok"
    assert result.evidence_count == 7
    raw_rows = read_jsonl(tmp_path / connector_runner.CONNECTOR_RAW_FILE)
    assert len(raw_rows) == 7
    assert all(row["entity"]["org"] == SUBSCRIPTION for row in raw_rows)


def test_azure_connector_sync_upserts_stable_event_ids(tmp_path: Path) -> None:
    append_config_event(tmp_path, connector_id="azure-posture", state="enabled", actor="a")
    first = connector_runner.run_connector_sync(tmp_path, connector_id="azure-posture", fixture_dir=FIXTURE)
    second = connector_runner.run_connector_sync(
        tmp_path,
        connector_id="azure-posture",
        fixture_dir=FIXTURE,
        materialize=False,
    )
    assert first.evidence_count == second.evidence_count == 7
    assert len(read_jsonl(tmp_path / connector_runner.CONNECTOR_RAW_FILE)) == 7


def test_azure_connector_sync_requires_enabled_connector(tmp_path: Path) -> None:
    with pytest.raises(connector_runner.ConnectorSyncError, match="not enabled") as exc:
        connector_runner.run_connector_sync(tmp_path, connector_id="azure-posture", fixture_dir=FIXTURE)
    assert exc.value.run["result"] == "error"


def test_azure_connector_sync_without_fixture_or_creds_errors(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    append_config_event(tmp_path, connector_id="azure-posture", state="enabled", actor="a")
    with pytest.raises(connector_runner.ConnectorSyncError, match="requires --fixture-dir"):
        connector_runner.run_connector_sync(tmp_path, connector_id="azure-posture")


def test_azure_client_rejects_incomplete_collection_when_policy_sdk_missing() -> None:
    client = AzureClient.__new__(AzureClient)
    client._policy = None

    with pytest.raises(RuntimeError, match="policy collection unavailable"):
        client.policy_assignments()


def test_azure_cli_client_reads_cloud_shell_json(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_which(executable: str) -> str:
        assert executable == "az"
        return "/usr/bin/az"

    def fake_run(
        cmd: list[str],
        *,
        check: bool,
        capture_output: bool,
        text: bool,
        timeout: int,
    ) -> SimpleNamespace:
        assert check is True
        assert capture_output is True
        assert text is True
        assert timeout == 90
        calls.append(cmd)
        if cmd[1:4] == ["role", "assignment", "list"]:
            payload: list[dict[str, Any]] = [{"id": "role-1", "roleDefinitionName": "Reader"}]
        elif cmd[1:4] == ["policy", "assignment", "list"]:
            payload = [{"id": "policy-1", "properties": {"enforcementMode": "Default"}}]
        elif cmd[1:3] == ["resource", "list"]:
            payload = [{"id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a"}]
        else:  # pragma: no cover - defensive branch for unexpected command shape
            payload = []
        return SimpleNamespace(stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr("security_lakehouse.connectors_azure.shutil.which", fake_which)
    monkeypatch.setattr("security_lakehouse.connectors_azure.subprocess.run", fake_run)

    client = AzureCliClient("sub")

    assert client.role_assignments() == [{"id": "role-1", "roleDefinitionName": "Reader"}]
    assert client.policy_assignments() == [{"id": "policy-1", "properties": {"enforcementMode": "Default"}}]
    assert client.resources() == [
        {"id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a"}
    ]
    assert all("--subscription" in call for call in calls)
    assert all(call[-4:] == ["--subscription", "sub", "--output", "json"] for call in calls)


class _StubAzureClient:
    """In-memory Azure client for exercising role-definition resolution.

    Mirrors the live SDK shape where ``role_assignments`` carry only a
    ``roleDefinitionId`` (a GUID path) and the display name must be resolved from
    a separate ``role_definitions`` catalog.
    """

    def __init__(
        self,
        subscription_id: str,
        *,
        role_assignments: list[dict[str, Any]],
        role_definitions: list[dict[str, Any]] | RuntimeError,
    ) -> None:
        self.subscription_id = subscription_id
        self._role_assignments = role_assignments
        self._role_definitions = role_definitions

    def role_assignments(self) -> list[dict[str, Any]]:
        return self._role_assignments

    def role_definitions(self) -> list[dict[str, Any]]:
        if isinstance(self._role_definitions, RuntimeError):
            raise self._role_definitions
        return self._role_definitions

    def policy_assignments(self) -> list[dict[str, Any]]:
        return []

    def resources(self) -> list[dict[str, Any]]:
        return []


def _assignment_id_only(sub: str, role_definition_id: str, *, scope: str) -> dict[str, Any]:
    return {
        "id": f"/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments/ra-{role_definition_id[-4:]}",
        "properties": {
            "roleDefinitionId": role_definition_id,
            "principalId": "bbbb1111-1111-1111-1111-111111111111",
            "principalType": "User",
            "scope": scope,
        },
    }


def test_role_name_resolved_from_role_definition_id_revives_privileged_detection() -> None:
    # The live SDK omits the role display name; without resolution privileged
    # detection silently dies. Owner at subscription scope must surface as high.
    owner_def_id = (
        f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization"
        "/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
    )
    client = _StubAzureClient(
        SUBSCRIPTION,
        role_assignments=[_assignment_id_only(SUBSCRIPTION, owner_def_id, scope=f"/subscriptions/{SUBSCRIPTION}")],
        role_definitions=[
            {
                "id": owner_def_id,
                "name": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                "properties": {"roleName": "Owner"},
            }
        ],
    )

    rows = collect_azure_evidence(client, collected_at=datetime(2026, 6, 3, tzinfo=UTC))

    assert validate_raw_events(rows) == []
    role = _by_type(rows, "azure.cloud.role_assignment")[0]
    assert role["attributes"]["role_name"] == "Owner"
    assert role["attributes"]["role_definition_id"] == owner_def_id
    assert role["attributes"]["privileged_role"] is True
    assert role["status"] == "open"
    assert role["severity"] == "high"


def test_role_resolution_is_best_effort_when_role_definitions_unreadable() -> None:
    # A least-privilege reader may lack roleDefinitions/read; collection must not
    # fail — the assignment is still emitted, just without a resolved name.
    role_def_id = (
        f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization"
        "/roleDefinitions/00000000-0000-0000-0000-000000000099"
    )
    client = _StubAzureClient(
        SUBSCRIPTION,
        role_assignments=[_assignment_id_only(SUBSCRIPTION, role_def_id, scope=f"/subscriptions/{SUBSCRIPTION}")],
        role_definitions=RuntimeError("AuthorizationFailed: roleDefinitions/read denied"),
    )

    rows = collect_azure_evidence(client, collected_at=datetime(2026, 6, 3, tzinfo=UTC))

    assert validate_raw_events(rows) == []
    role = _by_type(rows, "azure.cloud.role_assignment")[0]
    assert role["attributes"]["role_name"] == ""
    assert role["attributes"]["privileged_role"] is False
    assert role["attributes"]["role_definition_id"] == role_def_id


def test_azure_fixture_client_reads_role_definitions(tmp_path: Path) -> None:
    fixture = tmp_path / "az"
    fixture.mkdir()
    role_def_id = (
        f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization"
        "/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
    )
    (fixture / "role_assignments.json").write_text(
        json.dumps([_assignment_id_only(SUBSCRIPTION, role_def_id, scope=f"/subscriptions/{SUBSCRIPTION}")]),
        encoding="utf-8",
    )
    (fixture / "role_definitions.json").write_text(
        json.dumps(
            [{"id": role_def_id, "name": role_def_id.rsplit("/", 1)[-1], "properties": {"roleName": "Contributor"}}]
        ),
        encoding="utf-8",
    )

    client = AzureFixtureClient(fixture, subscription_id=SUBSCRIPTION)
    assert client.role_definitions()

    rows = collect_azure_evidence(client, collected_at=datetime(2026, 6, 3, tzinfo=UTC))
    role = _by_type(rows, "azure.cloud.role_assignment")[0]
    assert role["attributes"]["role_name"] == "Contributor"
    assert role["attributes"]["privileged_role"] is True


def test_azure_sync_uses_stored_subscription_id_when_env_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An enabled connector must sync off its configured subscription_id without
    # the operator re-exporting AZURE_SUBSCRIPTION_ID.
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    captured: dict[str, str] = {}

    class FixtureBackedAzureClient(AzureFixtureClient):
        def __init__(self, subscription_id: str) -> None:
            captured["subscription_id"] = subscription_id
            super().__init__(FIXTURE, subscription_id=subscription_id)

    monkeypatch.setattr(connectors_azure, "AzureClient", FixtureBackedAzureClient)

    append_config_event(
        tmp_path,
        connector_id="azure-posture",
        state="enabled",
        actor="a",
        credentials={"subscription_id": SUBSCRIPTION},
    )
    result = connector_runner.run_connector_sync(tmp_path, connector_id="azure-posture")

    assert result.result == "ok"
    assert result.evidence_count == 7
    assert captured["subscription_id"] == SUBSCRIPTION


def test_azure_adapter_is_registered_and_probe_reads_live(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert has_adapter("azure-posture") is True
    # Before enablement the probe is skipped (no synthetic collection signal).
    skipped = run_probe(tmp_path, connector_id="azure-posture")
    assert skipped["result"] == "skipped"
    assert "not enabled" in skipped["error"]

    class SubscriptionReader:
        def __init__(self, subscription_id: str) -> None:
            self.subscription_id = subscription_id

        def subscription(self) -> dict[str, str]:
            return {"subscriptionId": self.subscription_id, "state": "Enabled"}

    monkeypatch.setattr("security_lakehouse.connectors_azure.AzureClient", SubscriptionReader)
    append_config_event(
        tmp_path,
        connector_id="azure-posture",
        state="enabled",
        actor="a",
        credentials={"subscription_id": SUBSCRIPTION},
    )
    ok = run_probe(tmp_path, connector_id="azure-posture")
    # The probe proves a live subscription read; it never reports an evidence count.
    assert ok["result"] == "ok"
    assert ok["metadata"]["probe_mode"] == "live"
    assert ok["metadata"]["subscription_state"] == "Enabled"
    assert ok["evidence_count"] is None


@pytest.mark.parametrize("modern", [True, False])
def test_azure_sdk_namespace_compatibility(monkeypatch, modern: bool) -> None:
    import builtins

    original_import = builtins.__import__
    policy = SimpleNamespace(policy_assignments=SimpleNamespace(list=lambda: [{"id": "policy-test"}]))

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "azure.identity":
            return SimpleNamespace(DefaultAzureCredential=object)
        if name == "azure.mgmt.authorization":
            return SimpleNamespace(AuthorizationManagementClient=lambda *args: object())
        if name == "azure.mgmt.resource.resources" and modern:
            return SimpleNamespace(ResourceManagementClient=lambda *args: object())
        if name == "azure.mgmt.resource.policy" and modern:
            return SimpleNamespace(PolicyClient=lambda *args: policy)
        if name == "azure.mgmt.resource" and not modern:
            return SimpleNamespace(ResourceManagementClient=lambda *args: object(), PolicyClient=lambda *args: policy)
        if name.startswith("azure.mgmt.resource"):
            raise ImportError("SDK namespace absent")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    client = AzureClient(SUBSCRIPTION)
    assert client.policy_assignments() == [{"id": "policy-test"}]
