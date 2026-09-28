"""Mapping review responses never echo parser or exception detail."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

from security_lakehouse import api_v1
from security_lakehouse.mapping_review import review_attestation, review_log_path, verify_review_log

MARKER = "SECRET-MARKER-9f3c"


def _corrupt_log(lake: Path) -> Path:
    path = review_log_path(lake)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{{not json {MARKER}\n", encoding="utf-8")
    return path


def test_unparseable_decision_log_reports_a_fixed_issue(tmp_path: Path) -> None:
    path = _corrupt_log(tmp_path)
    log = verify_review_log(tmp_path)
    assert log["ok"] is False
    text = repr(log)
    assert MARKER not in text
    assert str(path) not in text
    assert "the decision log could not be parsed" in log["issues"]


def test_summary_endpoint_does_not_expose_parser_detail(tmp_path: Path) -> None:
    _corrupt_log(tmp_path)
    status, body = api_v1.handle_get("/api/v1/mapping-reviews/summary", {}, tmp_path)
    assert status == HTTPStatus.OK
    assert MARKER not in repr(body)


def test_attestation_does_not_expose_exception_text(tmp_path: Path) -> None:
    _corrupt_log(tmp_path)
    assert MARKER not in repr(review_attestation(tmp_path))


def test_queue_bad_request_does_not_echo_input(tmp_path: Path) -> None:
    status, body = api_v1.handle_get("/api/v1/mapping-reviews/queue", {"status": [MARKER]}, tmp_path)
    assert status == HTTPStatus.BAD_REQUEST
    assert MARKER not in repr(body)


def test_decisions_bad_request_does_not_expose_detail(tmp_path: Path) -> None:
    _corrupt_log(tmp_path)
    status, body = api_v1.handle_get("/api/v1/mapping-reviews/decisions", {}, tmp_path)
    assert MARKER not in repr(body)
    assert status in {HTTPStatus.OK, HTTPStatus.BAD_REQUEST}
