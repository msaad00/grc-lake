"""Provider settings use explicit adverse signals, with inventory kept unknown."""

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_lakehouse.connectors_azure import _role_assignment_event
from security_lakehouse.connectors_gcp import GCPClient, _iam_event
from security_lakehouse.connectors_kubernetes import _cluster_admin_event
from security_lakehouse.repo_governance import sync_repo_governance

NOW = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    "kind,name,expected",
    [
        ("Group", "system:unauthenticated", "open"),
        ("Group", "system:authenticated", "open"),
        ("User", "system:anonymous", "open"),
        ("Group", "system:serviceaccounts", "open"),
        ("Group", "system:masters", "observed"),
    ],
)
def test_cluster_admin_public_subjects_are_not_inventory(kind, name, expected):
    binding = {
        "metadata": {"name": "binding"},
        "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
        "subjects": [{"kind": kind, "name": name}],
    }
    assert _cluster_admin_event("cluster", binding, "ClusterRoleBinding", NOW, "tenant")["status"] == expected


@pytest.mark.parametrize(
    "member,expected",
    [("allUsers", "open"), ("allAuthenticatedUsers", "open"), ("user:reader@example.test", "observed")],
)
def test_gcp_public_reader_binding_is_not_inventory(member, expected):
    assert _iam_event("project", {"role": "roles/viewer", "members": [member]}, NOW, "tenant")["status"] == expected


def test_gcp_conditions_are_requested_preserved_and_keep_distinct_ids():
    def get_policy(*, request):
        assert request["options"]["requested_policy_version"] == 3
        return SimpleNamespace(
            bindings=[
                SimpleNamespace(
                    role="roles/viewer",
                    members=["user:reader@example.test"],
                    condition=SimpleNamespace(expression=expression, title="scoped"),
                )
                for expression in ["resource.name == 'one'", "resource.name == 'two'"]
            ]
        )

    client = object.__new__(GCPClient)
    client.project_id = "project"
    client._projects = SimpleNamespace(get_iam_policy=get_policy)
    bindings = client.iam_bindings()
    rows = [_iam_event("project", binding, NOW, "tenant") for binding in bindings]
    assert len({row["event_id"] for row in rows}) == 2
    assert {row["attributes"]["condition"]["expression"] for row in rows} == {
        "resource.name == 'one'",
        "resource.name == 'two'",
    }


@pytest.mark.parametrize(
    "scope,role,expected",
    [
        ("/", "Owner", "open"),
        ("/providers/Microsoft.Management/managementGroups/root", "Owner", "open"),
        ("/providers/Microsoft.Management/managementGroups/root", "Reader", "observed"),
        ("/subscriptions/sub/resourceGroups/one", "Owner", "observed"),
    ],
)
def test_azure_broad_privileged_assignment(scope, role, expected):
    assignment = {"id": "assignment", "properties": {"roleDefinitionName": role, "scope": scope}}
    assert _role_assignment_event("sub", assignment, NOW, "tenant")["status"] == expected


@pytest.mark.parametrize(
    "state,expected,severity",
    [("open", "open", "critical"), ("fixed", "observed", "info"), ("dismissed", "observed", "info")],
)
def test_repository_alert_state_and_severity_are_preserved(tmp_path, state, expected, severity):
    fixture = tmp_path / "fixtures"
    shutil.copytree(Path(__file__).parent / "fixtures/github-governance", fixture)
    (fixture / "security_findings.json").write_text(
        json.dumps({"code_scanning": [{"state": state, "rule": {"security_severity_level": "critical"}}]})
    )
    rows = sync_repo_governance("example/repository", fixture_dir=fixture, collected_at=NOW)
    row = next(row for row in rows if row["event_type"] == "repository.governance.security_findings")
    assert row["status"] == expected
    assert row["severity"] == severity


def test_closed_critical_alert_does_not_override_open_low_alert(tmp_path):
    fixture = tmp_path / "fixtures"
    shutil.copytree(Path(__file__).parent / "fixtures/github-governance", fixture)
    (fixture / "security_findings.json").write_text(
        json.dumps(
            {
                "code_scanning": [
                    {"state": "fixed", "rule": {"security_severity_level": "critical"}},
                    {"state": "open", "rule": {"security_severity_level": "low"}},
                ],
            }
        )
    )
    rows = sync_repo_governance("example/repository", fixture_dir=fixture, collected_at=NOW)
    row = next(row for row in rows if row["event_type"] == "repository.governance.security_findings")
    assert (row["status"], row["severity"]) == ("open", "low")


def test_conditional_binding_identity_is_stable_across_member_order():
    binding = {
        "role": "roles/viewer",
        "members": ["user:a@example.test", "user:b@example.test"],
        "condition": {"expression": "resource.name == 'one'", "title": "scoped"},
    }
    before = _iam_event("project", binding, NOW, "tenant")
    binding["members"].reverse()
    after = _iam_event("project", binding, NOW, "tenant")
    assert before == after
