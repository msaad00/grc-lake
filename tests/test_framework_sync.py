"""Regulator fetch resilience and partial-failure reporting for framework sync."""

from __future__ import annotations

import http.client
import io
import json
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

from security_lakehouse import framework_sync
from security_lakehouse.framework_sync import (
    USER_AGENT,
    format_sync_report,
    sync_frameworks,
)


class _Response:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def _http_error(code: int, headers: dict[str, str] | None = None) -> urllib.error.HTTPError:
    msg = Message()
    for key, value in (headers or {}).items():
        msg[key] = value
    return urllib.error.HTTPError("https://example.gov/x", code, "err", msg, io.BytesIO(b""))


class _Opener:
    """Replays a scripted sequence of responses/exceptions and records requests."""

    def __init__(self, script: list[Any]) -> None:
        self.script = list(script)
        self.requests: list[urllib.request.Request] = []

    def __call__(self, request: urllib.request.Request, timeout: float) -> _Response:
        self.requests.append(request)
        step = self.script.pop(0)
        if isinstance(step, BaseException):
            raise step
        return _Response(step)


def _registry(tmp_path: Path, *ids: str) -> Path:
    path = tmp_path / "registry.json"
    frameworks = [
        {
            "framework_id": fid,
            "official_source_url": f"https://example.gov/{fid}",
            "source_sha256": None,
            "pulled_at": None,
        }
        for fid in ids
    ]
    path.write_text(json.dumps({"frameworks": frameworks}), encoding="utf-8")
    return path


def test_user_agent_identifies_the_project_with_a_contact_url() -> None:
    assert "trustops-framework-sync/" in USER_AGENT
    assert "+https://github.com/" in USER_AGENT
    # A version, not a placeholder.
    version = USER_AGENT.split("trustops-framework-sync/")[1].split(";")[0]
    assert version and version[0].isdigit()


def test_fetch_sends_user_agent_and_accept_headers() -> None:
    opener = _Opener([b"body"])
    assert framework_sync._fetch("https://example.gov/x", opener=opener, sleep=lambda _s: None) == b"body"
    request = opener.requests[0]
    assert request.get_header("User-agent") == USER_AGENT
    assert request.get_header("Accept")


@pytest.mark.parametrize("code", [403, 429, 500, 502, 503, 504])
def test_fetch_retries_transient_status_then_succeeds(code: int) -> None:
    sleeps: list[float] = []
    opener = _Opener([_http_error(code), _http_error(code), b"ok"])
    body = framework_sync._fetch("https://example.gov/x", opener=opener, sleep=sleeps.append)
    assert body == b"ok"
    assert len(opener.requests) == 3
    assert len(sleeps) == 2
    assert sleeps[1] > sleeps[0] > 0  # exponential backoff


def test_fetch_honours_numeric_retry_after_with_a_cap() -> None:
    sleeps: list[float] = []
    opener = _Opener([_http_error(429, {"Retry-After": "7"}), _http_error(503, {"Retry-After": "9999"}), b"ok"])
    framework_sync._fetch("https://example.gov/x", opener=opener, sleep=sleeps.append)
    assert sleeps[0] == 7
    assert sleeps[1] == framework_sync.MAX_RETRY_DELAY_SECONDS


def test_fetch_does_not_retry_permanent_client_errors() -> None:
    opener = _Opener([_http_error(404), b"never"])
    with pytest.raises(urllib.error.HTTPError):
        framework_sync._fetch("https://example.gov/x", opener=opener, sleep=lambda _s: None)
    assert len(opener.requests) == 1


def test_fetch_gives_up_after_max_attempts() -> None:
    opener = _Opener([_http_error(503)] * framework_sync.MAX_ATTEMPTS)
    with pytest.raises(urllib.error.HTTPError):
        framework_sync._fetch("https://example.gov/x", opener=opener, sleep=lambda _s: None)
    assert len(opener.requests) == framework_sync.MAX_ATTEMPTS


def test_fetch_retries_connection_level_failures() -> None:
    opener = _Opener([urllib.error.URLError("reset"), TimeoutError("slow"), b"ok"])
    assert framework_sync._fetch("https://example.gov/x", opener=opener, sleep=lambda _s: None) == b"ok"


def test_one_failing_source_does_not_abort_the_others(tmp_path: Path) -> None:
    path = _registry(tmp_path, "good", "blocked", "truncated", "bad-url")

    def fetcher(url: str) -> bytes:
        if url.endswith("/blocked"):
            raise _http_error(403)
        if url.endswith("/truncated"):
            raise http.client.IncompleteRead(b"par")
        if url.endswith("/bad-url"):
            raise ValueError("unknown url type")
        return b"official"

    results = {r.framework_id: r for r in sync_frameworks(path, fetcher=fetcher)}
    assert results["good"].state == "updated"
    assert results["blocked"].state == "error"
    assert "403" in (results["blocked"].reason or "")
    assert results["truncated"].state == "error"
    assert results["bad-url"].state == "error"
    saved = {f["framework_id"]: f for f in json.loads(path.read_text(encoding="utf-8"))["frameworks"]}
    assert saved["good"]["source_sha256"]
    assert saved["blocked"]["source_sha256"] is None


def test_format_sync_report_lists_errors_and_counts() -> None:
    payload = {
        "count": 3,
        "results": [
            {"framework_id": "a", "state": "updated", "reason": None},
            {"framework_id": "b", "state": "unchanged", "reason": None},
            {"framework_id": "c", "state": "error", "reason": "fetch failed: HTTPError: HTTP Error 403: Forbidden"},
        ],
    }
    report = format_sync_report(payload)
    assert "1 updated" in report
    assert "1 unchanged" in report
    assert "1 error" in report
    assert "`c`" in report
    assert "403" in report


def test_format_sync_report_without_errors_says_so() -> None:
    report = format_sync_report({"count": 1, "results": [{"framework_id": "a", "state": "unchanged", "reason": None}]})
    assert "1 unchanged" in report
    assert "No source errors" in report


def test_format_sync_report_escapes_pipes_in_reasons() -> None:
    report = format_sync_report({"results": [{"framework_id": "x", "state": "error", "reason": "a|b"}]})
    assert "a\\|b" in report


def test_report_cli_reads_sync_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sync_json = tmp_path / "sync.json"
    sync_json.write_text(
        json.dumps({"count": 1, "results": [{"framework_id": "z", "state": "error", "reason": "boom"}]}),
        encoding="utf-8",
    )
    assert framework_sync.main(["report", str(sync_json)]) == 0
    assert "`z`" in capsys.readouterr().out
