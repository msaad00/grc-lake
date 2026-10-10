"""Lake commands that read the application database refuse a schema behind head."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("alembic")

from security_lakehouse import pipeline
from security_lakehouse.db import migrate
from security_lakehouse.generation_retention import retained_generations
from security_lakehouse.generations import active_generation

RAW = Path(__file__).resolve().parents[1] / "data/raw/security_events.jsonl"
OLD_REVISION = "0019_task_resolution_note"


@pytest.fixture
def stale_lake(tmp_path: Path) -> Path:
    lake = tmp_path / "lake"
    pipeline.run_pipeline(RAW, lake)
    migrate.upgrade(lake, revision=OLD_REVISION)
    return lake


def test_pipeline_refuses_stale_database_before_publishing(stale_lake: Path) -> None:
    before = active_generation(stale_lake)
    with pytest.raises(ValueError, match=r"grc-lake db upgrade --lake") as excinfo:
        pipeline.run_pipeline(RAW, stale_lake)
    message = str(excinfo.value)
    assert OLD_REVISION in message
    assert str(stale_lake) in message
    assert active_generation(stale_lake) == before


def test_pipeline_runs_after_upgrade(stale_lake: Path) -> None:
    migrate.upgrade(stale_lake)
    pipeline.run_pipeline(RAW, stale_lake)


def test_retention_refuses_stale_database(stale_lake: Path) -> None:
    with pytest.raises(ValueError, match=r"grc-lake db upgrade --lake"):
        retained_generations(stale_lake)


def test_require_head_accepts_current_and_rejects_unversioned(tmp_path: Path) -> None:
    current = tmp_path / "current"
    migrate.upgrade(current)
    migrate.require_head(current)

    unversioned = tmp_path / "unversioned"
    (unversioned / "server").mkdir(parents=True)
    (unversioned / "server" / "app.db").touch()
    with pytest.raises(ValueError, match=r"no schema revision.*grc-lake db upgrade --lake"):
        migrate.require_head(unversioned)
