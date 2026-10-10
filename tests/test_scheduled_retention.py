"""Scheduled retention runs the CLI archival functions on an operator-configured cadence."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from security_lakehouse import scheduled_retention, scheduler
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_tenant
from security_lakehouse.execution_mode import server_execution, server_tenant_id
from security_lakehouse.generation_retention import archive_generations
from security_lakehouse.generations import active_generation, pin_generation
from security_lakehouse.operation_jobs import root_key
from security_lakehouse.pipeline import run_pipeline
from security_lakehouse.server_app import create_app
from test_generations import RAW

ROOT = Path(__file__).resolve().parents[1]
ENV = (
    "GRC_LAKE_RETENTION_SCHEDULE",
    "GRC_LAKE_RETENTION_ARCHIVE_DIR",
    "GRC_LAKE_RETENTION_OLDER_THAN_DAYS",
    "GRC_LAKE_RETENTION_KEEP_LATEST",
)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    for key in (*ENV, "GRC_LAKE_COMMERCIAL_HOSTED", "GRC_LAKE_DATABASE_URL"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(scheduler, "_scheduled_lake_eval", lambda lake: None)


def _old_generation(lake: Path) -> Path:
    run_pipeline(RAW, lake)
    old = active_generation(lake)
    assert old is not None
    os.utime(old, (1, 1))
    run_pipeline(RAW, lake)
    return old


def _enable(monkeypatch, archive: Path | None, schedule: str = "@daily") -> None:
    monkeypatch.setenv("GRC_LAKE_RETENTION_SCHEDULE", schedule)
    monkeypatch.setenv("GRC_LAKE_RETENTION_OLDER_THAN_DAYS", "1")
    monkeypatch.setenv("GRC_LAKE_RETENTION_KEEP_LATEST", "1")
    if archive is not None:
        monkeypatch.setenv("GRC_LAKE_RETENTION_ARCHIVE_DIR", str(archive))


def _retention(rows: list[dict]) -> dict[str, dict]:
    return {row["target_id"]: row for row in rows if row.get("target_kind") == "retention"}


def test_unconfigured_retention_never_runs(tmp_path, monkeypatch):
    lake = tmp_path / "lake"
    old = _old_generation(lake)
    monkeypatch.setattr(scheduled_retention, "archive_generations", pytest.fail)
    monkeypatch.setattr(scheduled_retention, "archive_operational_history", pytest.fail)
    monkeypatch.setenv("GRC_LAKE_RETENTION_ARCHIVE_DIR", str(tmp_path / "archive"))

    assert _retention(scheduler.tick(lake)) == {}
    assert old.exists()
    assert not (lake / "gold" / scheduled_retention.RUNS_FILE).exists()
    assert not (tmp_path / "archive").exists()


def test_schedule_without_archive_only_previews(tmp_path, monkeypatch):
    lake = tmp_path / "lake"
    old = _old_generation(lake)
    _enable(monkeypatch, archive=None)

    rows = _retention(scheduler.tick(lake))

    assert rows["generations"]["result"] == "ok"
    assert rows["generations"]["mode"] == "preview"
    assert rows["generations"]["report"]["candidates"] == [old.name]
    assert rows["generations"]["report"]["archived"] == []
    assert rows["operational"]["mode"] == "preview"
    assert old.exists()


def test_scheduled_run_archives_records_and_waits_for_next_period(tmp_path, monkeypatch):
    lake, archive = tmp_path / "lake", tmp_path / "archive"
    old = _old_generation(lake)
    active = active_generation(lake)
    _enable(monkeypatch, archive)
    now = datetime.now(UTC)

    rows = _retention(scheduler.tick(lake, now=now))

    assert rows["generations"]["result"] == "ok"
    assert rows["generations"]["mode"] == "archive"
    assert rows["generations"]["report"]["archived"] == [old.name]
    assert rows["operational"]["result"] == "ok"
    assert not old.exists()
    assert active_generation(lake) == active
    assert (archive / "generations" / root_key(lake) / old.name / "generation.json").is_file()
    runs = [json.loads(line) for line in (lake / "gold" / scheduled_retention.RUNS_FILE).read_text().splitlines()]
    assert [(run["target_id"], run["result"], run["actor"]) for run in runs] == [
        ("generations", "ok", "scheduler"),
        ("operational", "ok", "scheduler"),
    ]
    assert runs[0]["report"]["archived"] == [old.name]

    assert _retention(scheduler.tick(lake, now=now + timedelta(hours=1))) == {}
    again = _retention(scheduler.tick(lake, now=now + timedelta(hours=25)))
    assert again["generations"]["result"] == "ok"
    assert again["generations"]["report"]["archived"] == []


@pytest.mark.parametrize("protection", ["reader", "snapshot"])
def test_scheduled_run_honors_cli_protections(tmp_path, monkeypatch, protection):
    from security_lakehouse.assessment import write_assessment_snapshot

    lake = tmp_path / "lake"
    run_pipeline(RAW, lake)
    old = active_generation(lake)
    os.utime(old, (1, 1))
    if protection == "snapshot":
        write_assessment_snapshot(lake)
    _enable(monkeypatch, tmp_path / "archive")
    with pin_generation(lake) if protection == "reader" else contextlib.nullcontext():
        run_pipeline(RAW, lake)
        rows = _retention(scheduler.tick(lake))
    assert rows["generations"]["result"] == "ok"
    assert rows["generations"]["report"]["archived"] == []
    assert old.exists()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("GRC_LAKE_RETENTION_SCHEDULE", "sometimes"),
        ("GRC_LAKE_RETENTION_OLDER_THAN_DAYS", "0"),
        ("GRC_LAKE_RETENTION_KEEP_LATEST", "none"),
        ("GRC_LAKE_RETENTION_ARCHIVE_DIR", "relative/archive"),
    ],
)
def test_invalid_configuration_fails_closed_and_visibly(tmp_path, monkeypatch, name, value):
    lake = tmp_path / "lake"
    old = _old_generation(lake)
    _enable(monkeypatch, tmp_path / "archive")
    monkeypatch.setenv(name, value)

    rows = [row for row in scheduler.tick(lake) if row.get("target_kind") == "retention"]

    assert rows and all(row["result"] == "error" for row in rows)
    assert old.exists()


def test_archive_inside_the_lake_root_is_refused(tmp_path, monkeypatch):
    lake = tmp_path / "lake"
    old = _old_generation(lake)
    _enable(monkeypatch, lake / "archive")

    rows = _retention(scheduler.tick(lake))

    assert rows["generations"]["result"] == "error"
    assert old.exists()


def test_concurrent_ticks_run_retention_once(tmp_path, monkeypatch):
    lake = tmp_path / "lake"
    lake.mkdir()
    _enable(monkeypatch, tmp_path / "archive")
    entered, release = threading.Event(), threading.Event()
    calls: list[Path] = []

    def slow_archive(path, **kwargs):
        calls.append(path)
        entered.set()
        assert release.wait(10)
        return {"generation_count": 0, "total_bytes": 0, "candidates": [], "archived": []}

    monkeypatch.setattr(scheduled_retention, "archive_generations", slow_archive)
    monkeypatch.setattr(scheduled_retention, "archive_operational_history", lambda path, **kwargs: {})
    first: list[dict] = []
    worker = threading.Thread(target=lambda: first.extend(scheduler.tick(lake)))
    worker.start()
    try:
        assert entered.wait(10)
        assert scheduler.tick(lake) == [{"target_kind": None, "skipped_locked": True, "fired": []}]
    finally:
        release.set()
        worker.join(10)
    assert calls == [lake]
    assert _retention(first)["generations"]["result"] == "ok"
    assert _retention(scheduler.tick(lake)) == {}
    assert calls == [lake]


def test_hosted_root_runs_retention_per_registered_tenant(tmp_path, monkeypatch):
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenants = [create_tenant(session, slug=name, name=name).id for name in ("a", "b")]
    old = {tenant: _old_generation(tmp_path / "tenants" / tenant) for tenant in tenants}
    stray = _old_generation(tmp_path / "tenants" / "unregistered")
    monkeypatch.setenv("GRC_LAKE_COMMERCIAL_HOSTED", "1")
    archive = tmp_path.parent / (tmp_path.name + "-archive")
    _enable(monkeypatch, archive)
    seen: list[tuple[Path, str | None]] = []
    operational: list[tuple[Path, str | None]] = []

    def record_generations(path, **kwargs):
        seen.append((Path(path), server_tenant_id()))
        return archive_generations(path, **kwargs)

    def record_operational(path, **kwargs):
        operational.append((Path(path), server_tenant_id()))
        return {"archived_jobs": 0}

    monkeypatch.setattr(scheduled_retention, "archive_generations", record_generations)
    monkeypatch.setattr(scheduled_retention, "archive_operational_history", record_operational)

    rows = scheduler.tick(tmp_path)

    assert seen == [(tmp_path / "tenants" / tenant, tenant) for tenant in tenants]
    assert operational == [(tmp_path.resolve(), None)]
    by_tenant = {row.get("tenant_id"): row for row in rows if row.get("target_id") == "generations"}
    assert set(by_tenant) == set(tenants)
    assert all(row["report"]["archived"] == [old[row["tenant_id"]].name] for row in by_tenant.values())
    assert not any(path.exists() for path in old.values())
    assert stray.exists()
    roots = [row for row in rows if row.get("target_id") == "operational"]
    assert len(roots) == 1 and roots[0]["result"] == "ok" and "tenant_id" not in roots[0]

    assert [row for row in scheduler.tick(tmp_path) if row.get("target_kind") == "retention"] == []
    assert len(operational) == 1


def test_tenant_scoped_tick_never_compacts_root_operations(tmp_path, monkeypatch):
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenants = [create_tenant(session, slug=name, name=name).id for name in ("a", "b")]
    lake = tmp_path / "tenants" / tenants[0]
    _old_generation(lake)
    _enable(monkeypatch, tmp_path.parent / (tmp_path.name + "-archive"))
    monkeypatch.setattr(scheduled_retention, "archive_operational_history", pytest.fail)

    with server_execution(tenants[0]):
        rows = _retention(scheduler.tick(lake))

    assert set(rows) == {"generations"}
    assert rows["generations"]["result"] == "ok"


def test_interrupted_archive_resumes_from_a_verified_copy(tmp_path):
    lake, archive = tmp_path / "lake", tmp_path / "archive"
    old = _old_generation(lake)
    archive.mkdir()
    shutil.copytree(old, archive / old.name)

    report = archive_generations(lake, older_than_days=1, keep_latest=1, archive_to=archive)

    assert report["archived"] == [old.name]
    assert not old.exists()
    assert (archive / old.name / "generation.json").is_file()


def test_unverifiable_partial_archive_still_fails_closed(tmp_path):
    lake, archive = tmp_path / "lake", tmp_path / "archive"
    old = _old_generation(lake)
    archive.mkdir()
    shutil.copytree(old, archive / old.name)
    next(path for path in (archive / old.name).rglob("*") if path.is_file() and path.name != "generation.json").unlink()

    with pytest.raises(ValueError, match="reconcile"):
        archive_generations(lake, older_than_days=1, keep_latest=1, archive_to=archive)
    assert old.exists()


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
def test_helm_scheduler_retention_values_reach_only_the_cronjob():
    def render(*overrides: str) -> dict:
        args = ["helm", "template", "trustops", str(ROOT / "deploy/helm/grc-lake")]
        args += ["--set", "env[0].name=GRC_LAKE_COOKIE_SIGNING_KEY", "--set", "env[0].value=test-only-signing-key"]
        for item in overrides:
            args += ["--set", item]
        output = subprocess.run(args, capture_output=True, text=True, check=True).stdout
        return {doc["kind"]: doc for doc in yaml.safe_load_all(output) if doc}

    def env(document: dict, kind: str) -> dict:
        spec = document[kind]["spec"]
        pod = spec["jobTemplate"]["spec"]["template"]["spec"] if kind == "CronJob" else spec["template"]["spec"]
        return {item["name"]: item.get("value") for item in pod["containers"][0].get("env", [])}

    default = render()
    assert not any(name.startswith("GRC_LAKE_RETENTION_") for name in env(default, "CronJob"))
    configured = render(
        "scheduler.retention.schedule=@daily",
        "scheduler.retention.archiveDir=/mnt/archive",
        "scheduler.retention.olderThanDays=180",
        "scheduler.retention.keepLatest=5",
    )
    cron = env(configured, "CronJob")
    assert cron["GRC_LAKE_RETENTION_SCHEDULE"] == "@daily"
    assert cron["GRC_LAKE_RETENTION_ARCHIVE_DIR"] == "/mnt/archive"
    assert cron["GRC_LAKE_RETENTION_OLDER_THAN_DAYS"] == "180"
    assert cron["GRC_LAKE_RETENTION_KEEP_LATEST"] == "5"
    assert not any(name.startswith("GRC_LAKE_RETENTION_") for name in env(configured, "Deployment"))
