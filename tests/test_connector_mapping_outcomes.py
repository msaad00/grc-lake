"""Provider state and explicit mappings must not manufacture coverage."""

from datetime import UTC, datetime

import pytest

from security_lakehouse import connectors_azure as azure
from security_lakehouse import connectors_clickhouse as clickhouse
from security_lakehouse import connectors_jira as jira
from security_lakehouse import connectors_kubernetes as kubernetes
from security_lakehouse import connectors_s3 as s3
from security_lakehouse import connectors_snowflake as snowflake

NOW = datetime(2026, 10, 6, tzinfo=UTC)


@pytest.mark.parametrize("module", [s3, snowflake])
@pytest.mark.parametrize("mapping", [["CUSTOM-1"], "CUSTOM-1", "CUSTOM-1|CUSTOM-2", "CUSTOM-1,CUSTOM-2"])
def test_explicit_mappings_replace_unrelated_defaults(module, mapping):
    expected = (
        ["CUSTOM-1", "CUSTOM-2"] if isinstance(mapping, str) and ("|" in mapping or "," in mapping) else ["CUSTOM-1"]
    )
    assert module._controls({"controls": mapping}, ["SOC2-CC6.1"]) == expected


@pytest.mark.parametrize("module", [s3, snowflake])
@pytest.mark.parametrize("mapping", [[], None, 42, {"id": "A"}, ["A", None], ""])
def test_malformed_explicit_mappings_never_fall_back_to_defaults(module, mapping):
    with pytest.raises(ValueError, match="control"):
        module._controls({"controls": mapping}, ["SOC2-CC6.1"])


def test_clickhouse_scalar_control_mapping_is_one_identifier():
    row = clickhouse._raw_from_row({"event_id": "one", "control_ids": "SOC2-CC6.1"}, tenant_id="tenant")
    assert row["controls"] == ["SOC2-CC6.1"]


@pytest.mark.parametrize(
    "resolution", [None, "Won't Do", "Won't Fix", "Duplicate", "Cannot Reproduce", "custom-terminal"]
)
def test_jira_done_without_explicit_success_does_not_pass(resolution):
    fields = {
        "status": {"name": "Done", "statusCategory": {"key": "done"}},
        "resolution": {"name": resolution} if resolution else None,
    }
    event = jira._ticket_event("https://jira.example.test", "site", "SEC-1", fields, NOW, "tenant")
    assert event["status"] == "not_evaluated"


def test_jira_healthy_in_progress_transition_is_observation():
    fields = {"status": {"name": "In Progress", "statusCategory": {"key": "indeterminate"}}}
    assert (
        jira._transition_event("https://jira.example.test", "site", "SEC-1", fields, NOW, "tenant")["status"]
        == "observed"
    )


def test_jira_wont_do_status_cannot_be_overridden_by_a_success_resolution():
    fields = {"status": {"name": "Won’t Do", "statusCategory": {"key": "done"}}, "resolution": {"name": "Done"}}
    assert (
        jira._ticket_event("https://jira.example.test", "site", "SEC-1", fields, NOW, "tenant")["status"]
        == "not_evaluated"
    )


@pytest.mark.parametrize(
    "role_id,expected", [("8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "open"), ("unknown-role", "not_evaluated")]
)
def test_azure_missing_role_definition_retains_risk_or_uncertainty(role_id, expected):
    assignment = {
        "id": "assignment",
        "properties": {
            "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/" + role_id,
            "scope": "/subscriptions/sub",
            "principalId": "person",
        },
    }
    assert azure._role_assignment_event("sub", assignment, NOW, "tenant", {})["status"] == expected


@pytest.mark.parametrize("collection", ["containers", "initContainers", "ephemeralContainers"])
def test_kubernetes_dangerous_added_capability_is_a_finding(collection):
    spec = {
        collection: [
            {
                "name": "app",
                "securityContext": {
                    "runAsNonRoot": True,
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"add": ["SYS_ADMIN"]},
                },
            }
        ]
    }
    assert any("capabilit" in row["reason"] for row in kubernetes.pod_security_findings(spec))


def test_kubernetes_baseline_permitted_capability_does_not_false_fail():
    spec = {
        "containers": [
            {
                "name": "app",
                "securityContext": {
                    "runAsNonRoot": True,
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"add": ["NET_BIND_SERVICE"]},
                },
            }
        ]
    }
    assert not kubernetes.pod_security_findings(spec)
