"""action.slack + action.jira — built on the shared ``_http_post`` egress path.

These actions reuse the exact allowlist + SSRF guard + secret resolver + retry
machinery that ``action.webhook`` uses. The tests assert (a) Slack posts the
expected payload and never persists the resolved webhook secret, (b) Jira posts
to the right path with auth derived from a secret and parses the issue key
without persisting the secret, and (c) both are subject to the shared allowlist
and SSRF guard. All HTTP is monkeypatched; no test touches the network and the
retry backoff sleep is a no-op.
"""

from __future__ import annotations

import base64
import json
import urllib.request
from pathlib import Path

import pytest

import security_lakehouse.workflows as wf
from security_lakehouse import netguard

ALLOWLIST_ENV = "GRC_LAKE_WORKFLOW_EGRESS_ALLOWLIST"


class _FakeResponse:
    """Minimal stand-in for the urlopen context-manager response."""

    def __init__(self, status: int, body: bytes = b"ok") -> None:
        self.status = status
        self._body = body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self, amt: int | None = None) -> bytes:
        return self._body


def _capturing_urlopen(captured: list[urllib.request.Request], status: int = 200, body: bytes = b"ok"):
    def _urlopen(request, timeout=None, validate=None):  # noqa: ANN001, ARG001
        captured.append(request)
        return _FakeResponse(status, body)

    return _urlopen


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never actually sleep during retry backoff."""
    monkeypatch.setattr(wf, "_webhook_backoff_sleep", lambda _s: None)


@pytest.fixture(autouse=True)
def _public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default: every host resolves to a public IP unless a test overrides it."""

    def _getaddrinfo(host, port, *args, **kwargs):  # noqa: ANN001, ARG001
        return [(2, 1, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(netguard.socket, "getaddrinfo", _getaddrinfo)


def _allow(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(ALLOWLIST_ENV, value)


# --- (a) action.slack -----------------------------------------------------------


def test_slack_posts_expected_payload(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch, "hooks.slack.com")
    captured: list[urllib.request.Request] = []
    monkeypatch.setattr(netguard, "open_guarded", _capturing_urlopen(captured, status=200, body=b"ok"))

    out = wf.run_action(
        tmp_path,
        node_type="action.slack",
        params={
            "webhook_url": "https://hooks.slack.com/services/T0/B0/XXX",
            "text": "control SOC2-CC6.1 failed",
            "username": "trustops",
            "icon_emoji": ":rotating_light:",
            "channel": "#security",
        },
    )

    assert out["status_code"] == 200
    assert out["ok"] is True
    assert len(captured) == 1
    sent = captured[0]
    assert sent.get_method() == "POST"
    assert sent.full_url == "https://hooks.slack.com/services/T0/B0/XXX"
    assert json.loads(sent.data) == {
        "text": "control SOC2-CC6.1 failed",
        "username": "trustops",
        "icon_emoji": ":rotating_light:",
        "channel": "#security",
    }


def test_slack_webhook_secret_not_persisted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch, "hooks.slack.com")
    monkeypatch.setenv("GRC_LAKE_SECRET_SLACK_WEBHOOK", "https://hooks.slack.com/services/T0/B0/SECRET")
    captured: list[urllib.request.Request] = []
    monkeypatch.setattr(netguard, "open_guarded", _capturing_urlopen(captured))

    nodes = [
        {
            "id": "slack",
            "node_type": "action.slack",
            "params": {"webhook_url": "{{secret.SLACK_WEBHOOK}}", "text": "hello"},
        }
    ]
    saved = wf.save_workflow(tmp_path, workflow_id=None, name="slack", description="", nodes=nodes, edges=[])
    run = wf.run_workflow(tmp_path, workflow_id=saved["workflow_id"])

    assert run["result"] == "ok"
    slack = next(r for r in run["node_results"] if r["node_id"] == "slack")
    assert slack["result"] == "ok"
    assert slack["output"]["ok"] is True
    # The secret reached the wire (resolved on the outbound copy only).
    assert captured[0].full_url == "https://hooks.slack.com/services/T0/B0/SECRET"
    # Recorded params keep the token form, never the resolved value.
    assert slack["params"]["webhook_url"] == "{{secret.SLACK_WEBHOOK}}"
    # The whole persisted run log must not contain the secret value.
    runs_file = tmp_path / "gold" / "workflow_runs.jsonl"
    assert "B0/SECRET" not in runs_file.read_text(encoding="utf-8")
    assert "B0/SECRET" not in json.dumps(run)


def test_slack_requires_text(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch, "hooks.slack.com")
    with pytest.raises(ValueError, match="slack 'text' is required"):
        wf.run_action(
            tmp_path,
            node_type="action.slack",
            params={"webhook_url": "https://hooks.slack.com/x"},
        )


# --- (b) action.jira ------------------------------------------------------------


def test_jira_posts_to_issue_path_with_basic_auth(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch, "org.atlassian.net")
    monkeypatch.setenv("GRC_LAKE_SECRET_JIRA_TOKEN", "jira-api-token")
    captured: list[urllib.request.Request] = []
    monkeypatch.setattr(
        netguard,
        "open_guarded",
        _capturing_urlopen(captured, status=201, body=b'{"id":"10001","key":"SEC-42","self":"https://x"}'),
    )

    out = wf.run_action(
        tmp_path,
        node_type="action.jira",
        params={
            "base_url": "https://org.atlassian.net",
            "project_key": "SEC",
            "summary": "auto: control failed",
            "description": "raised by workflow",
            "issue_type": "Bug",
            "email": "bot@org.com",
            "token": "{{secret.JIRA_TOKEN}}",
        },
    )

    assert out["status_code"] == 201
    assert out["ok"] is True
    assert out["issue_key"] == "SEC-42"

    sent = captured[0]
    assert sent.get_method() == "POST"
    assert sent.full_url == "https://org.atlassian.net/rest/api/3/issue"
    # Basic auth built from email + resolved secret.
    expected_basic = "Basic " + base64.b64encode(b"bot@org.com:jira-api-token").decode("ascii")
    assert sent.get_header("Authorization") == expected_basic
    body = json.loads(sent.data)
    assert body["fields"]["project"] == {"key": "SEC"}
    assert body["fields"]["summary"] == "auto: control failed"
    assert body["fields"]["issuetype"] == {"name": "Bug"}
    assert body["fields"]["description"] == "raised by workflow"


def test_jira_bearer_auth_and_default_issue_type(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch, "org.atlassian.net")
    monkeypatch.setenv("GRC_LAKE_SECRET_JIRA_TOKEN", "bearer-token")
    captured: list[urllib.request.Request] = []
    monkeypatch.setattr(
        netguard,
        "open_guarded",
        _capturing_urlopen(captured, status=201, body=b'{"key":"OPS-7"}'),
    )

    out = wf.run_action(
        tmp_path,
        node_type="action.jira",
        params={
            "base_url": "https://org.atlassian.net/",
            "project_key": "OPS",
            "summary": "ticket",
            "token": "{{secret.JIRA_TOKEN}}",
        },
    )

    assert out["issue_key"] == "OPS-7"
    sent = captured[0]
    assert sent.get_header("Authorization") == "Bearer bearer-token"
    # Trailing slash on base_url is normalized (no double slash).
    assert sent.full_url == "https://org.atlassian.net/rest/api/3/issue"
    body = json.loads(sent.data)
    assert body["fields"]["issuetype"] == {"name": "Task"}


def test_jira_secret_not_persisted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch, "org.atlassian.net")
    monkeypatch.setenv("GRC_LAKE_SECRET_JIRA_TOKEN", "top-secret-jira")
    monkeypatch.setattr(
        netguard,
        "open_guarded",
        lambda req, timeout=None, validate=None: _FakeResponse(201, b'{"key":"SEC-1"}'),
    )

    nodes = [
        {
            "id": "jira",
            "node_type": "action.jira",
            "params": {
                "base_url": "https://org.atlassian.net",
                "project_key": "SEC",
                "summary": "auto",
                "email": "bot@org.com",
                "token": "{{secret.JIRA_TOKEN}}",
            },
        }
    ]
    saved = wf.save_workflow(tmp_path, workflow_id=None, name="jira", description="", nodes=nodes, edges=[])
    run = wf.run_workflow(tmp_path, workflow_id=saved["workflow_id"])

    assert run["result"] == "ok"
    jira = next(r for r in run["node_results"] if r["node_id"] == "jira")
    assert jira["result"] == "ok"
    assert jira["output"]["issue_key"] == "SEC-1"
    # Recorded params keep the token form, never the resolved value.
    assert jira["params"]["token"] == "{{secret.JIRA_TOKEN}}"
    # Neither the raw secret nor its base64 form is in the persisted run log.
    runs_file = tmp_path / "gold" / "workflow_runs.jsonl"
    log_text = runs_file.read_text(encoding="utf-8")
    assert "top-secret-jira" not in log_text
    b64 = base64.b64encode(b"bot@org.com:top-secret-jira").decode("ascii")
    assert b64 not in log_text
    assert "top-secret-jira" not in json.dumps(run)


def test_jira_requires_summary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch, "org.atlassian.net")
    with pytest.raises(ValueError, match="jira 'summary' is required"):
        wf.run_action(
            tmp_path,
            node_type="action.jira",
            params={"base_url": "https://org.atlassian.net", "project_key": "SEC", "token": "t"},
        )


# --- (c) shared guarantees hold for both new actions ----------------------------


def test_slack_non_allowlisted_host_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch, "hooks.slack.com")
    with pytest.raises(ValueError, match="not in the egress allowlist"):
        wf.run_action(
            tmp_path,
            node_type="action.slack",
            params={"webhook_url": "https://evil.example.org/x", "text": "hi"},
        )


def test_jira_non_allowlisted_host_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch, "org.atlassian.net")
    with pytest.raises(ValueError, match="not in the egress allowlist"):
        wf.run_action(
            tmp_path,
            node_type="action.jira",
            params={
                "base_url": "https://evil.example.org",
                "project_key": "SEC",
                "summary": "x",
                "token": "t",
            },
        )


def test_slack_egress_denied_when_allowlist_unset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(ALLOWLIST_ENV, raising=False)
    with pytest.raises(ValueError, match="workflow egress is disabled"):
        wf.run_action(
            tmp_path,
            node_type="action.slack",
            params={"webhook_url": "https://hooks.slack.com/x", "text": "hi"},
        )


@pytest.mark.parametrize("resolved_ip", ["127.0.0.1", "169.254.169.254", "10.0.0.5", "::1"])
def test_slack_ssrf_private_resolution_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, resolved_ip: str
) -> None:
    _allow(monkeypatch, "hooks.slack.com")
    family = 10 if ":" in resolved_ip else 2
    monkeypatch.setattr(
        netguard.socket,
        "getaddrinfo",
        lambda *a, **k: [(family, 1, 6, "", (resolved_ip, 0))],
    )
    with pytest.raises(ValueError, match="SSRF blocked"):
        wf.run_action(
            tmp_path,
            node_type="action.slack",
            params={"webhook_url": "https://hooks.slack.com/x", "text": "hi"},
        )


@pytest.mark.parametrize("resolved_ip", ["127.0.0.1", "169.254.169.254", "192.168.1.1"])
def test_jira_ssrf_private_resolution_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, resolved_ip: str
) -> None:
    _allow(monkeypatch, "org.atlassian.net")
    monkeypatch.setattr(
        netguard.socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", (resolved_ip, 0))],
    )
    with pytest.raises(ValueError, match="SSRF blocked"):
        wf.run_action(
            tmp_path,
            node_type="action.jira",
            params={
                "base_url": "https://org.atlassian.net",
                "project_key": "SEC",
                "summary": "x",
                "token": "t",
            },
        )
