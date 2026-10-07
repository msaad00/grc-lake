"""Google Workspace identity-evidence connector runner tests (fixture-backed)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from security_lakehouse.connector_runner import CONNECTOR_RAW_FILE, ConnectorSyncError, run_connector_sync
from security_lakehouse.connector_state import (
    append_config_event,
    has_adapter,
    latest_run,
    run_probe,
)
from security_lakehouse.connectors_google_workspace import (
    GoogleWorkspaceClient,
    GoogleWorkspaceFixtureClient,
    collect_google_workspace_evidence,
)
from security_lakehouse.io import read_jsonl
from security_lakehouse.validation import validate_raw_events

FIXTURE = Path(__file__).parent / "fixtures" / "google_workspace"
CONNECTOR_ID = "google-workspace-identity"


def _by_asset(rows: list[dict], event_type: str) -> dict[str, dict]:
    return {r["entity"]["asset_id"]: r for r in rows if r["event_type"] == event_type}


def test_google_workspace_follows_next_page_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Directory API pages with nextPageToken; a single GET truncates a real
    tenant at maxResults. The client must follow the cursor to completion."""
    monkeypatch.setattr("security_lakehouse.ingestion.backoff.time.sleep", lambda *_: None)
    pages = {
        "": {"users": [{"id": "1"}, {"id": "2"}], "nextPageToken": "PAGE2"},
        "PAGE2": {"users": [{"id": "3"}]},  # no nextPageToken → last page
    }
    seen_tokens: list[str] = []

    def fake_open_public(request: object, **_kwargs: object) -> object:
        url = request.full_url  # type: ignore[attr-defined]
        token = ""
        if "pageToken=" in url:
            token = url.split("pageToken=", 1)[1].split("&", 1)[0]
        seen_tokens.append(token)
        response = MagicMock()
        response.read.return_value = json.dumps(pages[token]).encode("utf-8")
        response.__enter__.return_value = response
        return response

    with patch("security_lakehouse.netguard.open_public", side_effect=fake_open_public):
        users = GoogleWorkspaceClient("C123", access_token="tok").users()

    assert [u["id"] for u in users] == ["1", "2", "3"]
    assert seen_tokens == ["", "PAGE2"]  # followed exactly one cursor hop


def test_google_workspace_retries_on_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

    monkeypatch.setattr("security_lakehouse.ingestion.backoff.time.sleep", lambda *_: None)
    response = MagicMock()
    response.read.return_value = json.dumps({"groups": [{"id": "g1"}]}).encode("utf-8")
    response.__enter__.return_value = response
    sequence: list[object] = [
        urllib.error.HTTPError("https://admin.googleapis.com", 429, "slow", {"Retry-After": "0"}, None),
        response,
    ]

    def flaky(*_args: object, **_kwargs: object) -> object:
        item = sequence.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    with patch("security_lakehouse.netguard.open_public", side_effect=flaky):
        groups = GoogleWorkspaceClient("C123", access_token="tok").groups()

    assert [g["id"] for g in groups] == ["g1"]
    assert sequence == []


def test_collect_google_workspace_evidence_is_schema_valid_and_mapped() -> None:
    client = GoogleWorkspaceFixtureClient(FIXTURE)
    rows = collect_google_workspace_evidence(client, collected_at=datetime(2026, 5, 28, tzinfo=UTC))

    assert validate_raw_events(rows) == []
    # 3 users -> 3 identity + 3 mfa events; 2 groups -> 2 group events.
    assert len(rows) == 8

    identity = _by_asset(rows, "google_workspace.identity.user_access")
    mfa = _by_asset(rows, "google_workspace.identity.mfa_enrollment")
    group = [r for r in rows if r["event_type"] == "google_workspace.identity.group_membership"]
    assert len(identity) == 3
    assert len(mfa) == 3
    assert len(group) == 2

    # Every emitted event maps to identity controls that exist in the catalog.
    for row in rows:
        assert row["source"] == "google_workspace"
        assert "SOC2-CC6.1" in row["controls"]

    # 2SV-enrolled active user passes; active user without 2SV is a high-severity
    # open finding; the suspended account cannot authenticate.
    enrolled = mfa["google_workspace:user:100000000000000000001"]
    assert enrolled["status"] == "pass"
    assert enrolled["attributes"]["mfa_enrolled"] is True

    missing = mfa["google_workspace:user:100000000000000000002"]
    assert missing["status"] == "open"
    assert missing["severity"] == "high"
    assert missing["attributes"]["needs_mfa"] is True

    suspended = mfa["google_workspace:user:100000000000000000003"]
    assert suspended["status"] == "observed"
    assert suspended["attributes"]["needs_mfa"] is False

    # The suspended account surfaces as an open identity-access signal.
    suspended_access = identity["google_workspace:user:100000000000000000003"]
    assert suspended_access["status"] == "open"
    assert suspended_access["attributes"]["can_authenticate"] is False

    # Asset + evidence shapes are Workspace-scoped and point at the read-only API.
    sample = identity["google_workspace:user:100000000000000000001"]
    assert sample["entity"]["asset_type"] == "identity_account"
    assert sample["evidence"]["evidence_ref"].endswith("/users/100000000000000000001")

    # Group with an OWNER role is flagged as an elevated-membership open signal.
    by_group = _by_asset(rows, "google_workspace.identity.group_membership")
    elevated = by_group["google_workspace:group:200000000000000000001"]
    assert elevated["status"] == "open"
    assert elevated["attributes"]["has_elevated_role"] is True
    assert elevated["attributes"]["member_count"] == 2
    assert "/members" in elevated["evidence"]["evidence_ref"]

    flat = by_group["google_workspace:group:200000000000000000002"]
    assert flat["status"] == "observed"
    assert flat["attributes"]["has_elevated_role"] is False


def test_google_workspace_connector_sync_writes_raw_and_materializes_lake(tmp_path: Path) -> None:
    append_config_event(tmp_path, connector_id=CONNECTOR_ID, state="enabled", actor="alice")
    result = run_connector_sync(
        tmp_path,
        connector_id=CONNECTOR_ID,
        fixture_dir=FIXTURE,
    )
    assert result.result == "ok"
    assert result.evidence_count == 8
    assert result.materialized is True

    raw_rows = read_jsonl(tmp_path / CONNECTOR_RAW_FILE)
    assert validate_raw_events(raw_rows) == []
    assert len(raw_rows) == 8
    assert all(r["source"] == "google_workspace" for r in raw_rows)
    assert (tmp_path / "bronze" / "raw_events.jsonl").is_file()
    assert (tmp_path / "silver" / "normalized_events.jsonl").is_file()
    assert (tmp_path / "gold" / "current_posture.json").is_file()

    run = latest_run(tmp_path, CONNECTOR_ID, kind="sync")
    assert run["result"] == "ok"
    assert run["evidence_count"] == 8


def test_google_workspace_connector_sync_upserts_stable_event_ids(tmp_path: Path) -> None:
    append_config_event(tmp_path, connector_id=CONNECTOR_ID, state="enabled", actor="a")
    first = run_connector_sync(tmp_path, connector_id=CONNECTOR_ID, fixture_dir=FIXTURE)
    second = run_connector_sync(
        tmp_path,
        connector_id=CONNECTOR_ID,
        fixture_dir=FIXTURE,
        materialize=False,
    )
    assert first.evidence_count == second.evidence_count == 8
    assert len(read_jsonl(tmp_path / CONNECTOR_RAW_FILE)) == 8


def test_google_workspace_connector_sync_requires_enabled_connector(tmp_path: Path) -> None:
    with pytest.raises(ConnectorSyncError, match="not enabled") as exc:
        run_connector_sync(tmp_path, connector_id=CONNECTOR_ID, fixture_dir=FIXTURE)
    assert exc.value.run["result"] == "error"


def test_google_workspace_connector_sync_without_fixture_or_creds_errors(
    tmp_path: Path,
    monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    monkeypatch.delenv("GOOGLE_WORKSPACE_CUSTOMER_ID", raising=False)
    monkeypatch.delenv("GOOGLE_WORKSPACE_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("__provider_default__", raising=False)
    append_config_event(tmp_path, connector_id=CONNECTOR_ID, state="enabled", actor="a")
    with pytest.raises(ConnectorSyncError, match="requires --fixture-dir"):
        run_connector_sync(tmp_path, connector_id=CONNECTOR_ID)


def test_google_workspace_adapter_is_registered_and_probe_reports_ok(tmp_path: Path) -> None:
    assert has_adapter(CONNECTOR_ID) is True
    # Before enablement the probe is skipped (no synthetic collection signal).
    skipped = run_probe(tmp_path, connector_id=CONNECTOR_ID)
    assert skipped["result"] == "skipped"
    assert "not enabled" in skipped["error"]

    append_config_event(tmp_path, connector_id=CONNECTOR_ID, state="enabled", actor="a")
    ok = run_probe(tmp_path, connector_id=CONNECTOR_ID)
    # Adapter-available -> probe is "ok", not "skipped", and reports no count.
    assert ok["result"] == "ok"
    assert ok["evidence_count"] is None
