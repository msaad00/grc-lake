"""Dedicated tests for lake evaluation runs."""

from __future__ import annotations

from pathlib import Path

from security_lakehouse.connector_state import append_config_event
from security_lakehouse.ingestion_metrics import build_eval_accuracy
from security_lakehouse.ingestion_status import build_ingestion_status
from security_lakehouse.lake_eval import list_eval_runs, run_lake_eval
from security_lakehouse.models import PipelineResult
from security_lakehouse.pipeline import run_pipeline
from security_lakehouse.scale_synthesis import write_audit_scale_fixture
from security_lakehouse.scheduler import eval_schedule_status


def test_list_eval_runs_returns_newest_first(tmp_path: Path) -> None:
    lake = tmp_path / "lake"
    lake.mkdir()
    (lake / "raw").mkdir()
    write_audit_scale_fixture(lake / "raw" / "connector_events.jsonl", 12, controls_per_event=1, open_ratio=0.1, seed=1)
    first = run_lake_eval(lake, actor="first")
    second = run_lake_eval(lake, actor="second")
    assert first.result == "ok"
    assert second.result == "ok"

    runs = list_eval_runs(lake, limit=10)
    assert len(runs) == 2
    assert runs[0]["actor"] == "second"
    assert runs[1]["actor"] == "first"


def test_run_lake_eval_records_accuracy_snapshot(tmp_path: Path) -> None:
    lake = tmp_path / "lake"
    lake.mkdir()
    (lake / "raw").mkdir()
    write_audit_scale_fixture(lake / "raw" / "connector_events.jsonl", 20, controls_per_event=1, open_ratio=0.2, seed=2)
    result = run_lake_eval(lake, actor="accuracy-test")
    assert result.result == "ok"

    accuracy = build_eval_accuracy(lake)
    assert accuracy["total_tests"] > 0
    assert accuracy["pass_rate"] is not None

    latest = list_eval_runs(lake, limit=1)[0]
    assert latest["control_tests_total"] == accuracy["total_tests"]
    assert latest["control_tests_passing"] == accuracy["passing"]
    assert latest["pass_rate"] == accuracy["pass_rate"]


def test_run_lake_eval_warehouse_required_is_error(tmp_path: Path, monkeypatch) -> None:
    lake = tmp_path / "lake"
    lake.mkdir()
    (lake / "raw").mkdir()
    write_audit_scale_fixture(
        lake / "raw" / "connector_events.jsonl",
        5,
        controls_per_event=1,
        open_ratio=0.0,
        seed=3,
    )

    def _force_warehouse_required(_lake, _raw, *, env=None):
        return {
            "mode": "warehouse_required",
            "recommendation": "configure warehouse sink",
            "event_count": 200_000,
            "silver_count": 0,
        }

    monkeypatch.setattr(
        "security_lakehouse.lake_eval.resolve_materialize_strategy",
        _force_warehouse_required,
    )
    result = run_lake_eval(lake, actor="warehouse-test")
    assert result.result == "error"
    assert result.error
    latest = list_eval_runs(lake, limit=1)[0]
    assert latest["result"] == "error"
    assert latest.get("control_tests_total") is None


def test_run_lake_eval_uses_local_incremental_after_initial_materialize(tmp_path: Path) -> None:
    lake = tmp_path / "lake"
    raw = lake / "raw" / "connector_events.jsonl"
    raw.parent.mkdir(parents=True)
    write_audit_scale_fixture(raw, 18, controls_per_event=1, open_ratio=0.1, seed=6)

    first = run_lake_eval(lake, actor="initial")
    assert first.result == "ok"
    assert first.mode == "local_full"
    assert (lake / "manifest.json").is_file()

    second = run_lake_eval(lake, actor="incremental")
    assert second.result == "ok"
    assert second.mode == "local_incremental"


def test_run_lake_eval_warehouse_path_lands_when_sink_configured(tmp_path: Path, monkeypatch) -> None:
    lake = tmp_path / "lake"
    raw = lake / "raw" / "connector_events.jsonl"
    raw.parent.mkdir(parents=True)
    write_audit_scale_fixture(raw, 8, controls_per_event=1, open_ratio=0.0, seed=7)
    run_pipeline(raw, lake)

    def _warehouse_strategy(_lake, _raw, *, env=None):
        return {
            "mode": "warehouse",
            "event_count": 8,
            "silver_count": 8,
            "warehouse_row_threshold": 100_000,
            "warehouse_sink_configured": True,
        }

    def _land(_lake, _env):
        return {"sink": "duckdb", "rows": 8}

    monkeypatch.setattr(
        "security_lakehouse.lake_eval.resolve_materialize_strategy",
        _warehouse_strategy,
    )
    monkeypatch.setattr("security_lakehouse.lake_eval.land_if_configured", _land)

    result = run_lake_eval(lake, actor="warehouse-test", env={"DUCKDB_PATH": "/tmp/trustops.duckdb"})
    assert result.result == "ok"
    assert result.mode == "warehouse"
    assert result.pipeline is not None
    assert isinstance(result.pipeline, PipelineResult)


def test_eval_schedule_status_marks_never_fired_as_overdue(tmp_path: Path) -> None:
    lake = tmp_path / "lake"
    lake.mkdir()
    append_config_event(
        lake,
        connector_id="github-security",
        state="enabled",
        actor="alice",
        options={"sync_schedule": "every 15m", "eval_schedule": "every 6h"},
    )

    status = eval_schedule_status(lake)
    assert status["last_fired_at"] is None
    assert status["next_eval_at"] is not None
    assert status["eval_overdue"] is True


def test_ingestion_status_surfaces_eval_overdue_before_first_eval(tmp_path: Path) -> None:
    lake = tmp_path / "lake"
    lake.mkdir()
    append_config_event(
        lake,
        connector_id="github-security",
        state="enabled",
        actor="alice",
        options={"sync_schedule": "every 15m", "eval_schedule": "every 6h"},
    )

    status = build_ingestion_status(lake)
    scale = status["scale"]
    assert scale["eval_overdue"] is True
    assert scale["latest_eval"] == {}
    assert any(row["action"] == "run_lake_eval" for row in status["recommended_actions"])


def test_ingestion_status_includes_latest_eval_after_run(tmp_path: Path) -> None:
    lake = tmp_path / "lake"
    raw = lake / "raw" / "connector_events.jsonl"
    raw.parent.mkdir(parents=True)
    write_audit_scale_fixture(raw, 12, controls_per_event=1, open_ratio=0.1, seed=8)
    append_config_event(
        lake,
        connector_id="github-security",
        state="enabled",
        actor="alice",
        options={"sync_schedule": "every 15m", "eval_schedule": "every 6h"},
    )

    run_lake_eval(lake, actor="test")
    status = build_ingestion_status(lake)
    assert status["scale"]["latest_eval"]["actor"] == "test"
    assert status["scale"]["latest_eval"]["result"] == "ok"


def test_failed_evaluation_preserves_operator_diagnostic_without_returning_it(tmp_path, monkeypatch, caplog):
    def fail(*args, **kwargs):
        raise RuntimeError("operator-only diagnostic marker")

    monkeypatch.setattr("security_lakehouse.lake_eval.normalize_raw_events", fail)
    result = run_lake_eval(tmp_path)
    assert result.result == "error"
    assert "diagnostic marker" not in str(result.to_dict())
    assert "operator-only diagnostic marker" in caplog.text
    assert "diagnostic marker" not in str(list_eval_runs(tmp_path))
