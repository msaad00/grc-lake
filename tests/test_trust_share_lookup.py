"""Trust-share token lookup: indexed, invalidated on write, tolerant of bad rows."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from security_lakehouse import scheduler, trust_share


def _shares_file(lake: Path) -> Path:
    return lake / "gold" / trust_share.SHARES_FILE


def _append(lake: Path, *rows: object) -> None:
    path = _shares_file(lake)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write((row if isinstance(row, str) else json.dumps(row)) + "\n")


def _share_row(token: str, *, share_id: str, expires_at: str, created_at: str = "2026-01-01T00:00:00Z") -> dict:
    return {
        "share_id": share_id,
        "role": "auditor",
        "scope": "posture_full",
        "expires_at": expires_at,
        "created_at": created_at,
        "revoked_at": None,
        "token_sha256": trust_share._hash_token(token),
    }


def test_repeat_lookups_do_not_reparse_an_unchanged_share_file(tmp_path: Path, monkeypatch) -> None:
    created = trust_share.create_share(tmp_path, role="auditor")
    calls: list[Path] = []
    original = trust_share._read_share_rows

    def counting(path: Path):
        calls.append(path)
        return original(path)

    monkeypatch.setattr(trust_share, "_read_share_rows", counting)
    for _ in range(5):
        assert trust_share.resolve_share(tmp_path, created["token"]) is not None
    assert trust_share.resolve_share(tmp_path, "trust_unknown") is None
    assert len(calls) <= 1


def test_lookup_sees_revocation_and_new_shares(tmp_path: Path) -> None:
    first = trust_share.create_share(tmp_path, role="auditor")
    assert trust_share.resolve_share(tmp_path, first["token"]) is not None

    trust_share.revoke_share(tmp_path, first["share_id"])
    assert trust_share.resolve_share(tmp_path, first["token"]) is None

    second = trust_share.create_share(tmp_path, role="auditor")
    assert trust_share.resolve_share(tmp_path, second["token"])["share_id"] == second["share_id"]


def test_lookup_sees_a_revocation_appended_by_another_process(tmp_path: Path) -> None:
    share = trust_share.create_share(tmp_path, role="auditor")
    assert trust_share.resolve_share(tmp_path, share["token"]) is not None
    record = {k: v for k, v in share.items() if k != "token"}
    record["revoked_at"] = "2099-01-01T00:00:00Z"
    record["created_at"] = "2099-01-01T00:00:00Z"
    _append(tmp_path, record)
    assert trust_share.resolve_share(tmp_path, share["token"]) is None


def test_non_object_rows_are_skipped(tmp_path: Path) -> None:
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    _append(tmp_path, "[1, 2]", '"text"', "7", "null", _share_row("trust_ok", share_id="s1", expires_at=future))
    assert [row["share_id"] for row in trust_share.list_shares(tmp_path)] == ["s1"]
    assert trust_share.resolve_share(tmp_path, "trust_ok") is not None


def test_expiry_compares_instants_not_strings(tmp_path: Path) -> None:
    """An offset timestamp that is still in the future must not read as expired
    just because its local wall-clock string sorts before the UTC 'now' string."""
    later = datetime.now(UTC) + timedelta(minutes=90)
    in_new_york = later.astimezone(timezone(timedelta(hours=-5))).isoformat()
    _append(tmp_path, _share_row("trust_offset", share_id="s-off", expires_at=in_new_york))
    assert trust_share.resolve_share(tmp_path, "trust_offset") is not None
    assert trust_share.list_shares(tmp_path)[0]["expired"] is False


def test_naive_expiry_is_treated_as_utc(tmp_path: Path) -> None:
    past = (datetime.now(UTC) - timedelta(minutes=5)).replace(tzinfo=None).isoformat()
    future = (datetime.now(UTC) + timedelta(minutes=30)).replace(tzinfo=None).isoformat()
    _append(
        tmp_path,
        _share_row("trust_past", share_id="s-past", expires_at=past),
        _share_row("trust_future", share_id="s-future", expires_at=future),
    )
    assert trust_share.resolve_share(tmp_path, "trust_past") is None
    assert trust_share.resolve_share(tmp_path, "trust_future") is not None


@pytest.fixture
def new_york_tz(monkeypatch):
    if not hasattr(time, "tzset"):
        pytest.skip("time.tzset unavailable")
    monkeypatch.setenv("TZ", "America/New_York")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def test_scheduler_state_treats_naive_timestamps_as_utc(tmp_path: Path, new_york_tz) -> None:
    gold = tmp_path / "gold"
    gold.mkdir()
    (gold / scheduler.STATE_FILE).write_text(
        json.dumps({"target_kind": "workflow", "target_id": "wf-1", "last_fired_at": "2026-06-01T10:00:00"}) + "\n",
        encoding="utf-8",
    )
    state = scheduler._read_state(tmp_path)
    assert state["workflow:wf-1"] == datetime(2026, 6, 1, 10, 0, tzinfo=UTC)


def test_scheduler_state_skips_non_object_rows(tmp_path: Path) -> None:
    gold = tmp_path / "gold"
    gold.mkdir()
    (gold / scheduler.STATE_FILE).write_text(
        "[1]\n"
        '"x"\n'
        + json.dumps({"target_kind": "workflow", "target_id": "wf-1", "last_fired_at": "2026-06-01T10:00:00Z"})
        + "\n",
        encoding="utf-8",
    )
    assert list(scheduler._read_state(tmp_path)) == ["workflow:wf-1"]


def test_bound_tenant_share_resolves_before_the_lake_has_any_data(tmp_path: Path) -> None:
    # No-auth mode on an empty lake writes shares under tenants/<bound>, and
    # the root is not yet a flat lake; the public link must still resolve.
    from security_lakehouse import tenancy

    tenant_dir = tenancy.tenant_lake(tmp_path, "insecure", bound_tenant="insecure")
    share = trust_share.create_share(tenant_dir, role="auditor")

    resolved = trust_share.resolve_share_from_root(tmp_path, share["token"], bound_tenant="insecure")

    assert resolved is not None
    assert resolved[1] == tenant_dir
