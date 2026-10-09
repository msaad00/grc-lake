"""Human-readable CLI output preserves the canonical assessment's semantics."""

from __future__ import annotations

import json
import tomllib
from importlib.metadata import version
from pathlib import Path

import pytest

from security_lakehouse import assessment
from security_lakehouse.cli import main


def test_version_uses_installed_distribution_metadata(capsys) -> None:
    expected = version("grc-lake")
    project = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())
    assert expected == project["project"]["version"]
    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == 0
    assert capsys.readouterr().out == f"grc-lake {expected}\n"


def test_summary_reports_the_golden_assessment_counts(tmp_path, capsys) -> None:
    lake = str(tmp_path / "lake")
    assert main(["fixtures", "load", "--company", "golden", "--out", lake, "--rebase-times"]) == 0
    capsys.readouterr()
    assert main(["assessment", "status", "--lake", lake]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert main(["assessment", "status", "--lake", lake, "--format", "summary"]) == 0
    output = capsys.readouterr().out
    posture = payload["posture"]
    assert f"Posture    {posture['score']} / 100  {posture['state']}" in output
    assert (
        f"Controls   {posture['control_count']} total, {posture['not_evaluated_control_count']} not evaluated, {posture['stale_control_count']} stale"
        in output
    )
    assert (
        f"Tests      {posture['failed_control_test_count']} failing, {posture['warning_control_test_count']} warning"
        in output
    )
    assert (
        f"Violations {posture['open_violation_count']} open ({posture['critical_violation_count']} critical, {posture['high_violation_count']} high)"
        in output
    )
    assert (
        f"Evidence   {payload['evidence_freshness']['count']} records, {posture['stale_evidence_count']} stale/expired/missing"
        in output
    )
    assert len(output.splitlines()) == 5


@pytest.mark.parametrize("format_args", [[], ["--format", "json"]])
def test_json_preserves_existing_serialization(monkeypatch, capsys, format_args, tmp_path) -> None:
    payload = {"z": ["évidence"], "posture": {"score": 3.14, "state": "critical"}, "a": None}
    monkeypatch.setattr(assessment, "build_current_posture", lambda *args, **kwargs: payload)
    assert main(["assessment", "status", "--lake", str(tmp_path), *format_args]) == 0
    assert capsys.readouterr().out == json.dumps(payload, indent=2, sort_keys=True) + "\n"


def test_summary_uses_aggregate_counts_once_not_truncated_details(monkeypatch, capsys, tmp_path) -> None:
    calls = []

    def build(lake, *, freshness_days):
        calls.append((lake, freshness_days))
        return {
            "posture": {
                "score": 42.5,
                "state": "attention_required",
                "control_count": 50,
                "not_evaluated_control_count": 7,
                "stale_control_count": 9,
                "failed_control_test_count": 12,
                "warning_control_test_count": 3,
                "open_violation_count": 1000,
                "critical_violation_count": 200,
                "high_violation_count": 300,
                "stale_evidence_count": 800,
            },
            "violations": [],
            "evidence_freshness": {"count": 2000, "stale_evidence": []},
        }

    monkeypatch.setattr(assessment, "build_current_posture", build)
    assert main(["assessment", "status", "--lake", str(tmp_path), "--freshness-days", "3", "--format", "summary"]) == 0
    assert calls == [(str(tmp_path), 3)]
    output = capsys.readouterr().out
    assert "50 total, 7 not evaluated, 9 stale" in output
    assert "1000 open (200 critical, 300 high)" in output
    assert "2000 records, 800 stale/expired/missing" in output


def test_empty_lake_summary_stays_not_evaluated(tmp_path, capsys) -> None:
    assert main(["assessment", "status", "--lake", str(tmp_path), "--format", "summary"]) == 0
    output = capsys.readouterr().out
    assert "not_evaluated" in output
    assert "Controls   0 total, 0 not evaluated, 0 stale" in output
    assert "Evidence   0 records, 0 stale/expired/missing" in output


@pytest.mark.parametrize("output_format", ["json", "summary"])
def test_failed_assessment_does_not_print_a_success_summary(monkeypatch, capsys, output_format, tmp_path) -> None:
    def fail(*args, **kwargs):
        raise RuntimeError("assessment unavailable")

    monkeypatch.setattr(assessment, "build_current_posture", fail)
    assert main(["assessment", "status", "--lake", str(tmp_path), "--format", output_format]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "error: assessment unavailable\n"
