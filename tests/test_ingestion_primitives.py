"""Resilient-pull primitives: watermark, paginate, backoff, merge.

Proves the two load-bearing properties end to end: a re-run over overlapping
data produces no duplicates (idempotency), and a simulated HTTP 429 triggers
backoff then succeeds.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path

import pytest

from security_lakehouse import netguard
from security_lakehouse.connector_runner import _upsert_raw_events, _write_mode
from security_lakehouse.connectors_okta import OktaClient, OktaFixtureClient, collect_okta_evidence
from security_lakehouse.ingestion import backoff
from security_lakehouse.ingestion.merge import dedupe_by_key
from security_lakehouse.ingestion.paginate import paginate
from security_lakehouse.ingestion.watermark import read_watermark, write_watermark

FIXTURE = Path(__file__).parent / "fixtures" / "okta"


# --- watermark --------------------------------------------------------------


def test_watermark_round_trip_latest_wins(tmp_path: Path) -> None:
    assert read_watermark(tmp_path, "okta") is None
    write_watermark(tmp_path, "okta", "cursor-1")
    write_watermark(tmp_path, "aws", "other")
    write_watermark(tmp_path, "okta", "cursor-2")
    assert read_watermark(tmp_path, "okta") == "cursor-2"
    assert read_watermark(tmp_path, "aws") == "other"


# --- paginate ---------------------------------------------------------------


def test_paginate_walks_pages_until_no_cursor() -> None:
    pages = {None: {"items": [1, 2], "next": "a"}, "a": {"items": [3], "next": None}}
    out = list(
        paginate(
            fetch_page=lambda c: pages[c],
            extract_items=lambda p: p["items"],
            next_cursor=lambda p: p["next"],
        )
    )
    assert out == [1, 2, 3]


def test_paginate_reports_incomplete_and_preserves_resume_cursor() -> None:
    pages = {None: {"items": [1], "next": "a"}, "a": {"items": [2], "next": "b"}, "b": {"items": [3], "next": None}}
    stream = paginate(lambda c: pages[c], lambda p: p["items"], lambda p: p["next"], max_pages=2)
    assert next(stream) == 1
    assert next(stream) == 2
    with pytest.raises(RuntimeError, match="incomplete") as caught:
        next(stream)
    assert caught.value.cursor == "b"
    assert caught.value.pages_fetched == 2
    assert list(
        paginate(lambda c: pages[c], lambda p: p["items"], lambda p: p["next"], start_cursor=caught.value.cursor)
    ) == [3]


@pytest.mark.parametrize("budget", [0, -1])
def test_paginate_rejects_invalid_budget(budget) -> None:
    with pytest.raises(ValueError, match="max_pages"):
        list(paginate(lambda c: {}, lambda p: [], lambda p: None, max_pages=budget))


def test_paginate_complete_at_budget_is_success() -> None:
    assert list(paginate(lambda c: {}, lambda p: [1], lambda p: None, max_pages=1)) == [1]


# --- backoff ----------------------------------------------------------------


def test_next_delay_honors_retry_after_and_cap() -> None:
    assert backoff.next_delay(0, retry_after=7, jitter=False) == 7
    assert backoff.next_delay(99, retry_after=999, cap=30) == 30
    assert backoff.next_delay(2, base=1, jitter=False) == 4


def test_retry_succeeds_after_transient_failures() -> None:
    calls = {"n": 0}
    slept: list[float] = []

    def flaky() -> str:
        calls["n"] += 1
        if calls["n"] < 3:
            raise urllib.error.HTTPError("u", 429, "rate", Message(), None)
        return "ok"

    out = backoff.retry(
        flaky,
        is_retryable=lambda e: isinstance(e, urllib.error.HTTPError) and e.code == 429,
        max_retries=5,
        sleep=slept.append,
    )
    assert out == "ok"
    assert calls["n"] == 3 and len(slept) == 2


def test_retry_does_not_retry_non_retryable() -> None:
    with pytest.raises(ValueError):
        backoff.retry(
            lambda: (_ for _ in ()).throw(ValueError("nope")),
            is_retryable=lambda e: isinstance(e, urllib.error.HTTPError),
            sleep=lambda _s: None,
        )


# --- merge (idempotency) ----------------------------------------------------


def test_dedupe_is_idempotent_over_overlapping_data() -> None:
    rows = [{"id": "a", "v": 1}, {"id": "b", "v": 1}]
    once = dedupe_by_key(rows, key=lambda r: r["id"])
    # Re-run over a superset that re-delivers the same rows (overlap) plus one new.
    twice = dedupe_by_key([*rows, *rows, {"id": "c", "v": 1}], key=lambda r: r["id"])
    assert [r["id"] for r in once] == ["a", "b"]
    assert [r["id"] for r in twice] == ["a", "b", "c"]  # no duplicates


def test_dedupe_recency_last_writer_wins() -> None:
    rows = [{"id": "a", "v": 1, "ts": 1}, {"id": "a", "v": 2, "ts": 2}]
    out = dedupe_by_key(rows, key=lambda r: r["id"], recency=lambda r: r["ts"])
    assert out == [{"id": "a", "v": 2, "ts": 2}]


def test_raw_upsert_is_idempotent_on_rerun(tmp_path: Path) -> None:
    rows = collect_okta_evidence(OktaFixtureClient(FIXTURE))
    raw = tmp_path / "raw" / "connector_events.jsonl"
    first = _upsert_raw_events(raw, rows, connector_id="okta-identity", write_mode="append")
    # Re-running the exact same sync must not double-count.
    second = _upsert_raw_events(raw, rows, connector_id="okta-identity", write_mode="append")
    assert len(first) == len(second)
    on_disk = raw.read_text().strip().splitlines()
    assert len(on_disk) == len(first)


def _ids(rows: list[dict]) -> set[str]:
    return {str(r["event_id"]) for r in rows}


def test_write_mode_resolves_from_catalog_data_shape() -> None:
    # current_state evidence is a snapshot; event-log evidence is append-only.
    assert _write_mode("azure-posture") == "snapshot"
    assert _write_mode("okta-identity") == "snapshot"
    assert _write_mode("github-security") == "append"
    # Unknown connectors fall back to the non-destructive default.
    assert _write_mode("does-not-exist") == "append"


def test_snapshot_mode_detects_deletions(tmp_path: Path) -> None:
    rows = collect_okta_evidence(OktaFixtureClient(FIXTURE))
    assert len(rows) > 1
    raw = tmp_path / "raw" / "connector_events.jsonl"

    full = _upsert_raw_events(raw, list(rows), connector_id="okta-identity", write_mode="snapshot")
    assert _ids(full) == _ids(rows)

    # An entity removed at the source must disappear on the next snapshot.
    reduced_input = list(rows[:-1])
    dropped_id = str(rows[-1]["event_id"])
    reduced = _upsert_raw_events(raw, reduced_input, connector_id="okta-identity", write_mode="snapshot")
    assert dropped_id not in _ids(reduced)
    assert _ids(reduced) == _ids(rows[:-1])


def test_snapshot_replace_isolates_other_connectors(tmp_path: Path) -> None:
    okta_rows = collect_okta_evidence(OktaFixtureClient(FIXTURE))
    azure_fixture = Path(__file__).parent / "fixtures" / "azure"
    from security_lakehouse.connectors_azure import AzureFixtureClient, collect_azure_evidence

    azure_rows = collect_azure_evidence(
        AzureFixtureClient(azure_fixture, subscription_id="11111111-1111-1111-1111-111111111111")
    )
    raw = tmp_path / "raw" / "connector_events.jsonl"

    _upsert_raw_events(raw, list(okta_rows), connector_id="okta-identity", write_mode="snapshot")
    both = _upsert_raw_events(raw, list(azure_rows), connector_id="azure-posture", write_mode="snapshot")
    assert _ids(okta_rows) <= _ids(both)
    assert _ids(azure_rows) <= _ids(both)

    # Re-syncing azure with fewer rows must not touch okta's evidence.
    after = _upsert_raw_events(raw, list(azure_rows[:-1]), connector_id="azure-posture", write_mode="snapshot")
    assert _ids(okta_rows) <= _ids(after)
    assert str(azure_rows[-1]["event_id"]) not in _ids(after)


def test_append_mode_accumulates_history(tmp_path: Path) -> None:
    rows = collect_okta_evidence(OktaFixtureClient(FIXTURE))
    first_half = list(rows[: len(rows) // 2])
    second_half = list(rows[len(rows) // 2 :])
    raw = tmp_path / "raw" / "connector_events.jsonl"

    _upsert_raw_events(raw, first_half, connector_id="github-security", write_mode="append")
    merged = _upsert_raw_events(raw, second_half, connector_id="github-security", write_mode="append")
    # Append never drops earlier events even when a later pull omits them.
    assert _ids(rows) <= _ids(merged)


# --- okta 429 backoff (wired into the client) -------------------------------


class _FakeResp:
    def __init__(self, body: object) -> None:
        self._body = json.dumps(body).encode("utf-8")
        self.headers = {"Link": ""}

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *_: object) -> bool:
        return False


def test_okta_client_retries_on_429_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backoff.time, "sleep", lambda _s: None)
    calls = {"n": 0}
    headers = Message()
    headers["Retry-After"] = "1"

    def fake_urlopen(_req, timeout=0, **_kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise urllib.error.HTTPError("https://org.okta.com", 429, "rate", headers, None)
        return _FakeResp([{"id": "u1"}, {"id": "u2"}])

    monkeypatch.setattr(netguard, "open_public", fake_urlopen)
    users = OktaClient("https://org.okta.com", token="t").users()
    assert [u["id"] for u in users] == ["u1", "u2"]
    assert calls["n"] == 2  # one 429, one success
