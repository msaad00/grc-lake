"""``security-lakehouse lake map --dry-run`` and ``lake presets``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_lakehouse import cli
from security_lakehouse.connector_runner import CONNECTOR_RAW_FILE
from security_lakehouse.connector_state import append_config_event
from security_lakehouse.ingestion.watermark import read_watermark

OCSF = Path(__file__).parent / "fixtures" / "ocsf"


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, dict]:
    code = cli.main(list(argv))
    out = capsys.readouterr().out
    return code, json.loads(out) if out.strip() else {}


def _spec_file(tmp_path: Path, **overrides: object) -> Path:
    spec = {
        "spec_version": 1,
        "name": "ct_api",
        "source": {"table": "db.cloud_trail_mgmt_2_0"},
        "filters": [{"column": "class_uid", "op": "eq", "value": 6003}],
        "fields": {
            "id": {"column": "metadata.uid"},
            "observed_at": {"column": "time", "format": "epoch_ms"},
            "asset_id": {"column": "resources[0].uid"},
        },
    }
    spec.update(overrides)
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


def test_dry_run_previews_mapped_rows_and_compiled_sql(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, report = _run(
        capsys,
        "lake",
        "map",
        "--mapping",
        str(_spec_file(tmp_path)),
        "--input",
        str(OCSF / "cloud_trail_mgmt_2_0.json"),
        "--dialect",
        "databricks",
        "--dry-run",
    )
    assert code == 0
    assert report["valid"] is True
    assert report["dry_run"] is True
    assert report["rows_read"] == 3
    assert report["mapped_count"] == 1
    assert report["filtered"] == 2
    assert report["errors"] == []
    [event] = report["preview"]
    assert event["entity"]["asset_id"] == "arn:aws:s3:::acme-audit-logs"
    assert report["query"]["dialect"] == "databricks"
    assert report["query"]["sql"].startswith("SELECT ")
    assert report["query"]["params"] == {"p0": 6003}


def test_dry_run_with_a_preset_and_limit(capsys: pytest.CaptureFixture[str]) -> None:
    code, report = _run(
        capsys,
        "lake",
        "map",
        "--preset",
        "ocsf/compliance_finding",
        "--table",
        "sec.sh_findings_2_0",
        "--input",
        str(OCSF / "sh_findings_2_0.json"),
        "--limit",
        "1",
        "--dry-run",
    )
    assert code == 0
    assert report["mapping"] == "ocsf_compliance_finding"
    assert report["mapped_count"] == 2
    assert len(report["preview"]) == 1


def test_row_errors_exit_2_with_row_numbers(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rows = tmp_path / "rows.jsonl"
    rows.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {"metadata": {"uid": "a"}, "time": 1, "class_uid": 6003, "resources": [{"uid": "r"}]},
                {"metadata": {"uid": "b"}, "time": "later", "class_uid": 6003, "resources": [{"uid": "r"}]},
            ]
        ),
        encoding="utf-8",
    )
    code, report = _run(
        capsys, "lake", "map", "--mapping", str(_spec_file(tmp_path)), "--input", str(rows), "--dry-run"
    )
    assert code == 2
    assert report["mapped_count"] == 1
    assert report["errors"] == [{"row": 2, "error": "fields.observed_at: cannot read time='later' as epoch_ms"}]


def test_invalid_spec_exits_1_with_every_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _spec_file(tmp_path, spec_version=3, name="Bad Name")
    code, report = _run(capsys, "lake", "map", "--mapping", str(path), "--dry-run")
    assert code == 1
    assert report["valid"] is False
    assert any(e.startswith("spec_version") for e in report["errors"])
    assert any(e.startswith("name") for e in report["errors"])


def test_without_dry_run_the_command_refuses(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(["lake", "map", "--mapping", str(_spec_file(tmp_path))])
    assert code == 1
    assert "--dry-run" in capsys.readouterr().err


def test_parquet_input_is_read_when_pyarrow_is_installed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pa = pytest.importorskip("pyarrow")
    import pyarrow.parquet as pq

    rows = json.loads((OCSF / "cloud_trail_mgmt_2_0.json").read_text(encoding="utf-8"))
    path = tmp_path / "rows.parquet"
    pq.write_table(
        pa.Table.from_pylist(
            [{k: r[k] for k in ("metadata", "time", "class_uid")} | {"resources": r.get("resources", [])} for r in rows]
        ),
        path,
    )
    code, report = _run(
        capsys, "lake", "map", "--mapping", str(_spec_file(tmp_path)), "--input", str(path), "--dry-run"
    )
    assert code == 0, report
    assert report["mapped_count"] == 1


def test_connector_preview_reads_through_the_configured_connector_without_writing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lake = tmp_path / "lake"
    append_config_event(
        lake,
        connector_id="clickhouse-telemetry-lake",
        state="enabled",
        actor="t",
        options={"mapping": {"preset": "ocsf/api_activity", "source": {"table": "cloud_trail_mgmt_2_0"}}},
    )
    code, report = _run(
        capsys,
        "lake",
        "map",
        "--lake",
        str(lake),
        "--connector-id",
        "clickhouse-telemetry-lake",
        "--fixture-dir",
        str(OCSF),
        "--dry-run",
    )
    assert code == 0, report
    assert report["mapped_count"] == 1
    assert report["preview"][0]["event_type"] == "ocsf.api_activity"
    assert not (lake / CONNECTOR_RAW_FILE).exists()
    assert read_watermark(lake, "clickhouse-telemetry-lake") is None


def test_presets_command_lists_the_ocsf_presets(capsys: pytest.CaptureFixture[str]) -> None:
    code, report = _run(capsys, "lake", "presets")
    assert code == 0
    names = {row["preset"] for row in report["presets"]}
    assert {"ocsf/authentication", "ocsf/security_finding"} <= names
    assert all("OCSF 1." in row["description"] for row in report["presets"])
