"""Okta identity-evidence connector runner tests (fixture-backed)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from security_lakehouse.connector_runner import CONNECTOR_RAW_FILE, ConnectorSyncError, run_connector_sync
from security_lakehouse.connector_state import (
    append_config_event,
    has_adapter,
    latest_run,
    run_probe,
)
from security_lakehouse.connectors_okta import OktaFixtureClient, collect_okta_evidence
from security_lakehouse.io import read_jsonl
from security_lakehouse.validation import validate_raw_events

FIXTURE = Path(__file__).parent / "fixtures" / "okta"


def _by_asset(rows: list[dict], event_type: str) -> dict[str, dict]:
    return {r["entity"]["asset_id"]: r for r in rows if r["event_type"] == event_type}


def test_collect_okta_evidence_is_schema_valid_and_mapped() -> None:
    client = OktaFixtureClient(FIXTURE)
    rows = collect_okta_evidence(client, collected_at=datetime(2026, 5, 28, tzinfo=UTC))

    assert validate_raw_events(rows) == []
    # 3 users -> 3 identity + 3 mfa events; 2 policies -> 2 policy events.
    assert len(rows) == 8

    identity = _by_asset(rows, "okta.identity.user_access")
    mfa = _by_asset(rows, "okta.identity.mfa_enrollment")
    policy = [r for r in rows if r["event_type"] == "okta.identity.mfa_policy"]
    assert len(identity) == 3
    assert len(mfa) == 3
    assert len(policy) == 2

    # Every emitted event maps to identity controls that exist in the catalog.
    for row in rows:
        assert row["source"] == "okta"
        assert "SOC2-CC6.1" in row["controls"]

    # MFA-enrolled active user passes; active user without a usable factor is a
    # high-severity open finding; the deprovisioned account cannot authenticate.
    enrolled = mfa["okta:user:00u1mfaenrolled01"]
    assert enrolled["status"] == "pass"
    assert enrolled["attributes"]["mfa_enrolled"] is True
    assert enrolled["attributes"]["active_factor_count"] == 2

    missing = mfa["okta:user:00u2nomfa00000002"]
    assert missing["status"] == "open"
    assert missing["severity"] == "high"
    assert missing["attributes"]["needs_mfa"] is True

    deprovisioned = mfa["okta:user:00u3deprovision03"]
    assert deprovisioned["status"] == "observed"
    assert deprovisioned["attributes"]["needs_mfa"] is False

    # Asset + evidence shapes are Okta-scoped and point at the read-only API.
    sample = identity["okta:user:00u1mfaenrolled01"]
    assert sample["entity"]["asset_type"] == "identity_account"
    assert sample["evidence"]["evidence_ref"].endswith("/api/v1/users/00u1mfaenrolled01")

    org_policy = policy[0]
    assert org_policy["entity"]["asset_id"].startswith("okta:org:")
    assert "/api/v1/policies/" in org_policy["evidence"]["evidence_ref"]


def test_okta_connector_sync_writes_raw_and_materializes_lake(tmp_path: Path) -> None:
    append_config_event(tmp_path, connector_id="okta-identity", state="enabled", actor="alice")
    result = run_connector_sync(
        tmp_path,
        connector_id="okta-identity",
        fixture_dir=FIXTURE,
    )
    assert result.result == "ok"
    assert result.evidence_count == 8
    assert result.materialized is True

    raw_rows = read_jsonl(tmp_path / CONNECTOR_RAW_FILE)
    assert validate_raw_events(raw_rows) == []
    assert len(raw_rows) == 8
    assert all(r["source"] == "okta" for r in raw_rows)
    assert (tmp_path / "bronze" / "raw_events.jsonl").is_file()
    assert (tmp_path / "silver" / "normalized_events.jsonl").is_file()
    assert (tmp_path / "gold" / "current_posture.json").is_file()

    run = latest_run(tmp_path, "okta-identity", kind="sync")
    assert run["result"] == "ok"
    assert run["evidence_count"] == 8


def test_okta_connector_sync_upserts_stable_event_ids(tmp_path: Path) -> None:
    append_config_event(tmp_path, connector_id="okta-identity", state="enabled", actor="a")
    first = run_connector_sync(tmp_path, connector_id="okta-identity", fixture_dir=FIXTURE)
    second = run_connector_sync(
        tmp_path,
        connector_id="okta-identity",
        fixture_dir=FIXTURE,
        materialize=False,
    )
    assert first.evidence_count == second.evidence_count == 8
    assert len(read_jsonl(tmp_path / CONNECTOR_RAW_FILE)) == 8


def test_okta_connector_sync_requires_enabled_connector(tmp_path: Path) -> None:
    with pytest.raises(ConnectorSyncError, match="not enabled") as exc:
        run_connector_sync(tmp_path, connector_id="okta-identity", fixture_dir=FIXTURE)
    assert exc.value.run["result"] == "error"


def test_okta_connector_sync_without_fixture_or_creds_errors(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("OKTA_ORG_URL", raising=False)
    monkeypatch.delenv("OKTA_API_TOKEN", raising=False)
    monkeypatch.delenv("__provider_default__", raising=False)
    append_config_event(tmp_path, connector_id="okta-identity", state="enabled", actor="a")
    with pytest.raises(ConnectorSyncError, match="requires --fixture-dir"):
        run_connector_sync(tmp_path, connector_id="okta-identity")


def test_okta_adapter_is_registered_and_probe_reports_ok(tmp_path: Path) -> None:
    assert has_adapter("okta-identity") is True
    # Before enablement the probe is skipped (no synthetic collection signal).
    skipped = run_probe(tmp_path, connector_id="okta-identity")
    assert skipped["result"] == "skipped"
    assert "not enabled" in skipped["error"]

    append_config_event(tmp_path, connector_id="okta-identity", state="enabled", actor="a")
    ok = run_probe(tmp_path, connector_id="okta-identity")
    # Adapter-available -> probe is "ok", not "skipped", and reports no count.
    assert ok["result"] == "ok"
    assert ok["evidence_count"] is None
