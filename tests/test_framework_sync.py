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


def _write_sync_json(tmp_path: Path, rows: list[dict[str, Any]]) -> Path:
    sync_json = tmp_path / "sync.json"
    sync_json.write_text(json.dumps({"count": len(rows), "results": rows}), encoding="utf-8")
    return sync_json


def test_report_cli_reads_sync_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sync_json = _write_sync_json(
        tmp_path, [{"framework_id": "z", "state": "error", "reason": "boom", "transient": True}]
    )
    assert framework_sync.main(["report", str(sync_json)]) == 0
    assert "`z`" in capsys.readouterr().out


@pytest.mark.parametrize(
    "exc",
    [
        _http_error(403),
        _http_error(429),
        _http_error(500),
        _http_error(503),
        urllib.error.URLError(ConnectionRefusedError(61, "Connection refused")),
        urllib.error.URLError(OSError(8, "nodename nor servname provided")),
        TimeoutError("slow"),
        ConnectionResetError("reset"),
        http.client.IncompleteRead(b"par"),
    ],
)
def test_upstream_unavailability_is_transient(tmp_path: Path, exc: BaseException) -> None:
    path = _registry(tmp_path, "upstream")

    def fetcher(url: str) -> bytes:
        raise exc

    (result,) = sync_frameworks(path, fetcher=fetcher)
    assert result.state == "error"
    assert result.transient is True


@pytest.mark.parametrize(
    "exc",
    [
        _http_error(404),
        _http_error(401),
        _http_error(410),
        ValueError("unknown url type"),
        urllib.error.URLError("unknown url type: ftp"),
    ],
)
def test_broken_source_is_not_transient(tmp_path: Path, exc: BaseException) -> None:
    path = _registry(tmp_path, "broken")

    def fetcher(url: str) -> bytes:
        raise exc

    (result,) = sync_frameworks(path, fetcher=fetcher)
    assert result.state == "error"
    assert result.transient is False


def test_registry_entry_without_a_source_is_not_transient(tmp_path: Path) -> None:
    path = tmp_path / "registry.json"
    path.write_text(json.dumps({"frameworks": [{"framework_id": "nosrc"}]}), encoding="utf-8")
    (result,) = sync_frameworks(path, fetcher=lambda _url: b"x")
    assert result.state == "error"
    assert result.transient is False


def test_report_warns_and_passes_when_only_upstream_is_unavailable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sync_json = _write_sync_json(
        tmp_path,
        [
            {"framework_id": "soc2", "state": "updated", "reason": None, "transient": False},
            {
                "framework_id": "iso-27001-2022",
                "state": "error",
                "reason": "fetch failed: HTTPError: HTTP Error 403: Forbidden",
                "transient": True,
            },
        ],
    )
    assert framework_sync.main(["report", str(sync_json)]) == 0
    captured = capsys.readouterr()
    assert "`iso-27001-2022`" in captured.out
    assert "::warning" not in captured.out, "annotations must not leak into the Markdown report"
    warnings = [line for line in captured.err.splitlines() if line.startswith("::warning")]
    assert len(warnings) == 1
    assert "iso-27001-2022" in warnings[0] and "403" in warnings[0]
    assert "::error" not in captured.err


def test_report_fails_on_a_broken_source(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sync_json = _write_sync_json(
        tmp_path,
        [
            {"framework_id": "a", "state": "error", "reason": "fetch failed: HTTP Error 403", "transient": True},
            {"framework_id": "b", "state": "error", "reason": "fetch failed: HTTP Error 404", "transient": False},
        ],
    )
    assert framework_sync.main(["report", str(sync_json)]) == 1
    err = capsys.readouterr().err
    assert any(line.startswith("::warning") and "a:" in line for line in err.splitlines())
    assert any(line.startswith("::error") and "b:" in line and "404" in line for line in err.splitlines())


def test_report_treats_an_unclassified_error_as_a_failure(tmp_path: Path) -> None:
    sync_json = _write_sync_json(tmp_path, [{"framework_id": "old", "state": "error", "reason": "boom"}])
    assert framework_sync.main(["report", str(sync_json)]) == 1


def test_report_escapes_annotation_text(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sync_json = _write_sync_json(
        tmp_path,
        [{"framework_id": "x", "state": "error", "reason": "50% down\r\nnext", "transient": True}],
    )
    assert framework_sync.main(["report", str(sync_json)]) == 0
    (line,) = [line for line in capsys.readouterr().err.splitlines() if line.startswith("::warning")]
    assert "50%25 down%0D%0Anext" in line


def test_report_rejects_malformed_sync_json(tmp_path: Path) -> None:
    sync_json = tmp_path / "sync.json"
    sync_json.write_text("{not json", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        framework_sync.main(["report", str(sync_json)])


def test_sync_cli_reports_transient_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from security_lakehouse import cli

    def fake_sync(**_kwargs: Any) -> list[framework_sync.SyncResult]:
        return [framework_sync.SyncResult("a", "error", None, None, None, "fetch failed: 503", transient=True)]

    monkeypatch.setattr(framework_sync, "sync_frameworks", fake_sync)
    assert cli.main(["frameworks", "sync"]) == 0
    (row,) = json.loads(capsys.readouterr().out)["results"]
    assert row["transient"] is True
