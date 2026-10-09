"""S3 object-storage evidence connector tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from security_lakehouse import connector_runner, connector_state
from security_lakehouse.connectors_s3 import (
    S3FixtureClient,
    collect_s3_evidence,
    discover_s3_scope,
    probe_s3_access,
)
from security_lakehouse.io import read_jsonl
from security_lakehouse.validation import validate_raw_events

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "object-storage-evidence"


def test_collect_s3_fixture_evidence_validates() -> None:
    rows = collect_s3_evidence(
        S3FixtureClient(FIXTURE_DIR),
        collected_at=datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
    )

    assert len(rows) == 3
    assert validate_raw_events(rows) == []
    assert {row["source"] for row in rows} == {"s3"}
    assert {row["event_type"] for row in rows} == {
        "s3.evidence.attestation",
        "s3.evidence.sarif",
        "s3.evidence.audit_export",
    }
    assert any(row["status"] == "open" and row["severity"] == "high" for row in rows)


def test_s3_sync_writes_snapshot_raw_evidence(tmp_path: Path) -> None:
    connector_state.append_config_event(
        tmp_path,
        connector_id="object-storage-evidence",
        state="enabled",
        actor="alice",
        options={"bucket": "trustops-evidence", "prefix": "bundles/"},
    )

    result = connector_runner.run_connector_sync(
        tmp_path,
        connector_id="object-storage-evidence",
        fixture_dir=FIXTURE_DIR,
    )

    assert result.result == "ok"
    assert result.evidence_count == 3
    assert result.watermark_cursor is None
    raw_rows = read_jsonl(tmp_path / connector_runner.CONNECTOR_RAW_FILE)
    assert len(raw_rows) == 3
    assert validate_raw_events(raw_rows) == []
    run = connector_state.latest_run(tmp_path, "object-storage-evidence", kind="sync")
    assert run is not None
    assert run["result"] == "ok"


def test_s3_snapshot_replace_drops_removed_objects(tmp_path: Path) -> None:
    connector_state.append_config_event(
        tmp_path,
        connector_id="object-storage-evidence",
        state="enabled",
        actor="alice",
        options={"bucket": "trustops-evidence", "prefix": "bundles/"},
    )
    connector_runner.run_connector_sync(
        tmp_path,
        connector_id="object-storage-evidence",
        fixture_dir=FIXTURE_DIR,
    )

    # Second sync with a smaller fixture should replace prior rows for this connector.
    small_fixture = tmp_path / "small-fixture"
    small_fixture.mkdir()
    (small_fixture / "manifest.json").write_text(
        '[{"key":"bundles/only.json","size":1,"etag":"x","last_modified":"2026-06-02T00:00:00Z"}]',
        encoding="utf-8",
    )
    result = connector_runner.run_connector_sync(
        tmp_path,
        connector_id="object-storage-evidence",
        fixture_dir=small_fixture,
    )
    assert result.evidence_count == 1
    raw_rows = read_jsonl(tmp_path / connector_runner.CONNECTOR_RAW_FILE)
    assert len(raw_rows) == 1
    assert raw_rows[0]["attributes"]["key"] == "bundles/only.json"


def test_s3_probe_and_discovery_with_role() -> None:
    with patch("security_lakehouse.connectors_s3.S3Client") as mock_client:
        mock_client.return_value.probe.return_value = {
            "ok": True,
            "bucket": "trustops-evidence",
            "prefix": "bundles/",
            "object_count": 3,
            "error": None,
        }
        probe = probe_s3_access(
            credentials={"role_arn": "arn:aws:iam::123456789012:role/GrcLakeEvidenceRead"},
            options={"bucket": "trustops-evidence", "prefix": "bundles/"},
        )
    assert probe["ok"] is True
    assert probe["object_count"] == 3

    with patch("security_lakehouse.connectors_s3.S3Client") as mock_client:
        mock_client.return_value.discover_scope.return_value = {
            "ok": True,
            "selection_mode": "visible_prefixes",
            "selectors": [{"kind": "prefix", "name": "bundles/"}],
            "recommended_options": {"bucket": "trustops-evidence", "prefix": "bundles/"},
        }
        scope = discover_s3_scope(
            credentials={"role_arn": "arn:aws:iam::123456789012:role/GrcLakeEvidenceRead"},
            options={"bucket": "trustops-evidence", "prefix": "bundles/"},
        )
    assert scope["ok"] is True


def test_s3_probe_requires_bucket() -> None:
    with pytest.raises(ValueError, match="requires bucket"):
        probe_s3_access(credentials={}, options={"prefix": "bundles/"})


def test_s3_fixture_discovery_recommends_prefix() -> None:
    scope = S3FixtureClient(FIXTURE_DIR).discover_scope()
    assert scope["ok"] is True
    assert scope["recommended_options"]["prefix"] == "bundles/"
