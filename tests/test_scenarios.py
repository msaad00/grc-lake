"""End-to-end scenario runner tests."""

from __future__ import annotations

import json
from pathlib import Path

from security_lakehouse.cli import main
from security_lakehouse.scenarios import format_live_cloud_posture_summary, run_live_cloud_posture_scenario

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture_dirs() -> dict[str, str]:
    return {
        "azure-posture": str(FIXTURES / "azure"),
        "aws-posture": str(FIXTURES / "aws"),
        "snowflake-evidence-lake": str(FIXTURES / "snowflake"),
    }


def test_live_cloud_posture_scenario_runs_connectors_integrity_snapshot_and_workflow(tmp_path: Path) -> None:
    report = run_live_cloud_posture_scenario(
        tmp_path,
        connectors=["azure-posture", "aws-posture", "snowflake-evidence-lake"],
        fixture_dirs=_fixture_dirs(),
        actor="test",
    )

    assert report["summary"]["ok"] is True
    assert report["summary"]["connector_count"] == 3
    assert report["summary"]["successful_connectors"] == 3
    assert report["summary"]["failed_connectors"] == 0
    assert report["summary"]["evidence_count"] == 22
    assert report["summary"]["evidence_by_source"] == {"aws": 7, "azure": 7, "snowflake": 8}
    assert report["summary"]["sources"] == ["aws", "azure", "snowflake"]
    assert report["summary"]["event_type_count"] == 10
    assert report["summary"]["asset_count"] == 19
    assert report["summary"]["controls_referenced"] == 8
    assert report["summary"]["proof_state"] == "action_required"
    assert report["summary"]["source_breakdown"][0] == {
        "source": "aws",
        "evidence_count": 7,
        "asset_count": 4,
        "control_count": 5,
        "open_items": 3,
        "high_or_critical": 2,
        "top_event_types": [
            {"event_type": "aws.iam.user_access", "count": 3},
            {"event_type": "aws.iam.mfa_enrollment", "count": 3},
            {"event_type": "aws.iam.password_policy", "count": 1},
        ],
        "severity_counts": {"high": 2, "info": 4, "medium": 1},
    }
    assert report["summary"]["recommended_actions"] == [
        {
            "priority": "p1",
            "action": "triage_open_findings",
            "reason": "15 open violation(s) need owners or exceptions.",
        }
    ]
    assert report["summary"]["connector_results"] == [
        {
            "connector_id": "azure-posture",
            "ok": True,
            "evidence_count": 7,
            "materialized": True,
            "error": "",
        },
        {
            "connector_id": "aws-posture",
            "ok": True,
            "evidence_count": 7,
            "materialized": True,
            "error": "",
        },
        {
            "connector_id": "snowflake-evidence-lake",
            "ok": True,
            "evidence_count": 8,
            "materialized": True,
            "error": "",
        },
    ]
    assert report["integrity"]["ok"] is True
    assert report["snapshot_chain"]["ok"] is True
    assert report["snapshot_chain"]["length"] == 2
    assert report["workflow"]["run"]["result"] == "ok"
    assert (tmp_path / "gold" / "scenario_reports" / "live-cloud-posture.json").is_file()
    proof_pack = tmp_path / "gold" / "scenario_reports" / "live-cloud-posture.md"
    assert proof_pack.is_file()
    proof_text = proof_pack.read_text(encoding="utf-8")
    assert "# GRC Lake Live Cloud Proof Pack" in proof_text
    assert "| `snowflake-evidence-lake` | ok | 8 | yes |" in proof_text
    assert "`triage_open_findings`: 15 open violation(s) need owners or exceptions." in proof_text


def test_live_cloud_posture_scenario_cli_emits_report(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    code = main(
        [
            "scenario",
            "run",
            "live-cloud-posture",
            "--lake",
            str(tmp_path),
            "--connector",
            "azure-posture",
            "--connector",
            "aws-posture",
            "--connector",
            "snowflake-evidence-lake",
            "--fixture",
            f"azure-posture={FIXTURES / 'azure'}",
            "--fixture",
            f"aws-posture={FIXTURES / 'aws'}",
            "--fixture",
            f"snowflake-evidence-lake={FIXTURES / 'snowflake'}",
        ]
    )

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["scenario"] == "live-cloud-posture"
    assert payload["summary"]["ok"] is True
    assert payload["integrity"]["silver_count"] == 22


def test_live_cloud_posture_scenario_cli_can_emit_operator_summary(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    code = main(
        [
            "scenario",
            "run",
            "live-cloud-posture",
            "--lake",
            str(tmp_path),
            "--connector",
            "azure-posture",
            "--connector",
            "aws-posture",
            "--connector",
            "snowflake-evidence-lake",
            "--fixture",
            f"azure-posture={FIXTURES / 'azure'}",
            "--fixture",
            f"aws-posture={FIXTURES / 'aws'}",
            "--fixture",
            f"snowflake-evidence-lake={FIXTURES / 'snowflake'}",
            "--summary",
        ]
    )

    assert code == 0
    output = capsys.readouterr().out
    assert "GRC Lake scenario: live-cloud-posture" in output
    assert "Status: ok" in output
    assert "Evidence: 22 normalized rows from aws=7, azure=7, snowflake=8" in output
    assert "- azure-posture: ok, evidence=7, materialized" in output
    assert "Integrity: ok" in output
    assert "Snapshot chain: ok length=2" in output
    assert "Workflow: ok" in output
    assert "Proof pack:" in output


def test_live_cloud_posture_summary_formatter_handles_partial_failure(tmp_path: Path) -> None:
    report = run_live_cloud_posture_scenario(
        tmp_path,
        connectors=["aws-posture", "azure-posture"],
        fixture_dirs={"aws-posture": str(FIXTURES / "aws")},
        actor="test",
        continue_on_error=True,
    )

    output = format_live_cloud_posture_summary(report)
    assert "Status: needs attention" in output
    assert "- aws-posture: ok, evidence=7, materialized" in output
    assert "- azure-posture: failed" in output
