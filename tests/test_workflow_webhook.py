"""action.webhook — allowlist-gated egress, SSRF guard, secret resolver, retry.

All HTTP is monkeypatched: no test touches the network, and the retry backoff
sleep is replaced with a no-op so the suite stays fast.
"""

from __future__ import annotations

import io
import json
import urllib.error
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
    def _urlopen(request, timeout=None, validate=None):
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

    def _getaddrinfo(host, port, *args, **kwargs):
        return [(2, 1, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(netguard.socket, "getaddrinfo", _getaddrinfo)


def _allow(monkeypatch: pytest.MonkeyPatch, value: str = "hooks.example.com") -> None:
    monkeypatch.setenv(ALLOWLIST_ENV, value)


# --- (a) deny-by-default --------------------------------------------------------


def test_egress_denied_when_allowlist_unset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(ALLOWLIST_ENV, raising=False)
    with pytest.raises(ValueError, match="workflow egress is disabled"):
        wf.run_action(tmp_path, node_type="action.webhook", params={"url": "https://hooks.example.com/x"})


def test_egress_denied_when_allowlist_blank(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(ALLOWLIST_ENV, "   ,  ")
    with pytest.raises(ValueError, match="workflow egress is disabled"):
        wf.run_action(tmp_path, node_type="action.webhook", params={"url": "https://hooks.example.com/x"})


# --- (b) allowlisted host succeeds ----------------------------------------------


def test_allowlisted_host_succeeds(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch)
    captured: list[urllib.request.Request] = []
    monkeypatch.setattr(netguard, "open_guarded", _capturing_urlopen(captured, status=200, body=b'{"received":true}'))
    out = wf.run_action(
        tmp_path,
        node_type="action.webhook",
        params={"url": "https://hooks.example.com/incident", "body": {"alert": "fire"}},
    )
    assert out["status_code"] == 200
    assert out["ok"] is True
    assert out["response_snippet"] == '{"received":true}'
    assert len(captured) == 1
    assert captured[0].get_method() == "POST"
    assert json.loads(captured[0].data) == {"alert": "fire"}


def test_allowlist_host_port_match(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(ALLOWLIST_ENV, "hooks.example.com:8443")
    captured: list[urllib.request.Request] = []
    monkeypatch.setattr(netguard, "open_guarded", _capturing_urlopen(captured))
    out = wf.run_action(
        tmp_path,
        node_type="action.webhook",
        params={"url": "https://hooks.example.com:8443/x"},
    )
    assert out["ok"] is True


# --- (c) non-allowlisted host rejected ------------------------------------------


def test_non_allowlisted_host_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch, "hooks.example.com")
    with pytest.raises(ValueError, match="not in the egress allowlist"):
        wf.run_action(tmp_path, node_type="action.webhook", params={"url": "https://evil.example.org/x"})


def test_host_port_mismatch_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(ALLOWLIST_ENV, "hooks.example.com:443")
    # bare host listed only with :443; request to :8443 must not match.
    with pytest.raises(ValueError, match="not in the egress allowlist"):
        wf.run_action(tmp_path, node_type="action.webhook", params={"url": "https://hooks.example.com:8443/x"})


# --- (d) SSRF guard -------------------------------------------------------------


@pytest.mark.parametrize(
    "resolved_ip",
    ["127.0.0.1", "169.254.169.254", "10.0.0.5", "192.168.1.1", "::1"],
)
def test_ssrf_private_resolution_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, resolved_ip: str) -> None:
    _allow(monkeypatch)
    family = 10 if ":" in resolved_ip else 2
    monkeypatch.setattr(
        netguard.socket,
        "getaddrinfo",
        lambda *a, **k: [(family, 1, 6, "", (resolved_ip, 0))],
    )
    with pytest.raises(ValueError, match="SSRF blocked"):
        wf.run_action(tmp_path, node_type="action.webhook", params={"url": "https://hooks.example.com/x"})


def test_ssrf_localhost_literal_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(ALLOWLIST_ENV, "localhost")
    with pytest.raises(ValueError, match="localhost"):
        wf.run_action(tmp_path, node_type="action.webhook", params={"url": "http://localhost/x"})


def test_non_http_scheme_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch, "etc")
    with pytest.raises(ValueError, match="scheme"):
        wf.run_action(tmp_path, node_type="action.webhook", params={"url": "file:///etc/passwd"})
    with pytest.raises(ValueError, match="scheme"):
        wf.run_action(tmp_path, node_type="action.webhook", params={"url": "gopher://hooks.example.com/x"})


# --- (e) secret resolver never persists -----------------------------------------


def test_secret_resolved_into_request_but_not_persisted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch)
    monkeypatch.setenv("GRC_LAKE_SECRET_FOO", "super-secret-token")
    captured: list[urllib.request.Request] = []
    monkeypatch.setattr(netguard, "open_guarded", _capturing_urlopen(captured))

    out = wf.run_action(
        tmp_path,
        node_type="action.webhook",
        params={
            "url": "https://hooks.example.com/x",
            "headers": {"Authorization": "Bearer {{secret.FOO}}"},
            "body": {"token": "{{secret.FOO}}"},
        },
    )
    # The secret reached the wire.
    sent = captured[0]
    assert sent.get_header("Authorization") == "Bearer super-secret-token"
    assert json.loads(sent.data) == {"token": "super-secret-token"}
    # The output never echoes the resolved secret.
    assert "super-secret-token" not in json.dumps(out)


def test_unset_secret_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch)
    monkeypatch.delenv("GRC_LAKE_SECRET_MISSING", raising=False)
    monkeypatch.setattr(netguard, "open_guarded", _capturing_urlopen([]))
    with pytest.raises(ValueError, match="secret 'MISSING' is not set"):
        wf.run_action(
            tmp_path,
            node_type="action.webhook",
            params={"url": "https://hooks.example.com/x", "body": "{{secret.MISSING}}"},
        )


def test_run_log_keeps_secret_token_not_value(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch)
    monkeypatch.setenv("GRC_LAKE_SECRET_FOO", "super-secret-token")
    captured: list[urllib.request.Request] = []
    monkeypatch.setattr(netguard, "open_guarded", _capturing_urlopen(captured))

    nodes = [
        {
            "id": "hook",
            "node_type": "action.webhook",
            "params": {
                "url": "https://hooks.example.com/x",
                "headers": {"Authorization": "Bearer {{secret.FOO}}"},
            },
        }
    ]
    saved = wf.save_workflow(tmp_path, workflow_id=None, name="hook", description="", nodes=nodes, edges=[])
    run = wf.run_workflow(tmp_path, workflow_id=saved["workflow_id"])

    assert run["result"] == "ok"
    hook = next(r for r in run["node_results"] if r["node_id"] == "hook")
    assert hook["result"] == "ok"
    assert hook["output"]["ok"] is True
    # Recorded params carry the token form, never the resolved value.
    assert hook["params"]["headers"]["Authorization"] == "Bearer {{secret.FOO}}"

    # The whole persisted run log line must not contain the secret value.
    runs_file = tmp_path / "gold" / "workflow_runs.jsonl"
    assert "super-secret-token" not in runs_file.read_text(encoding="utf-8")


# --- (f) retry on 5xx + idempotency key -----------------------------------------


def test_retry_on_5xx_then_success(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch)
    seen_keys: list[str] = []
    calls = {"n": 0}

    def _urlopen(request, timeout=None, validate=None):
        seen_keys.append(request.get_header("Idempotency-key"))
        calls["n"] += 1
        if calls["n"] < 3:
            raise urllib.error.HTTPError(request.full_url, 503, "busy", hdrs=None, fp=io.BytesIO(b"busy"))
        return _FakeResponse(200, b"ok")

    monkeypatch.setattr(netguard, "open_guarded", _urlopen)
    out = wf.run_action(
        tmp_path,
        node_type="action.webhook",
        params={"url": "https://hooks.example.com/x", "max_retries": 2},
    )
    assert out["ok"] is True
    assert out["status_code"] == 200
    assert out["attempts"] == 3
    # Idempotency-Key present and stable across every retry.
    assert all(k is not None for k in seen_keys)
    assert len(set(seen_keys)) == 1


def test_retry_exhausted_returns_last_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch)

    def _urlopen(request, timeout=None, validate=None):
        raise urllib.error.HTTPError(request.full_url, 500, "boom", hdrs=None, fp=io.BytesIO(b"boom"))

    monkeypatch.setattr(netguard, "open_guarded", _urlopen)
    out = wf.run_action(
        tmp_path,
        node_type="action.webhook",
        params={"url": "https://hooks.example.com/x", "max_retries": 1},
    )
    assert out["ok"] is False
    assert out["status_code"] == 500
    assert out["attempts"] == 2
    assert out["error"] == "HTTP 500"


def test_idempotency_key_stable_across_replays(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch)
    keys: list[str] = []
    monkeypatch.setattr(
        netguard,
        "open_guarded",
        lambda req, timeout=None, validate=None: keys.append(req.get_header("Idempotency-key")) or _FakeResponse(200),
    )
    params = {"url": "https://hooks.example.com/x", "body": {"a": 1}}
    wf.run_action(tmp_path, node_type="action.webhook", params=dict(params))
    wf.run_action(tmp_path, node_type="action.webhook", params=dict(params))
    assert keys[0] == keys[1]


# --- (g) 4xx not retried --------------------------------------------------------


def test_4xx_not_retried(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch)
    calls = {"n": 0}

    def _urlopen(request, timeout=None, validate=None):
        calls["n"] += 1
        raise urllib.error.HTTPError(request.full_url, 404, "nope", hdrs=None, fp=io.BytesIO(b"nope"))

    monkeypatch.setattr(netguard, "open_guarded", _urlopen)
    out = wf.run_action(
        tmp_path,
        node_type="action.webhook",
        params={"url": "https://hooks.example.com/x", "max_retries": 3},
    )
    assert out["ok"] is False
    assert out["status_code"] == 404
    assert out["attempts"] == 1
    assert calls["n"] == 1


# --- normal workflow run with a webhook node ------------------------------------


def test_webhook_node_in_workflow_run_log(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _allow(monkeypatch)
    monkeypatch.setattr(netguard, "open_guarded", lambda req, timeout=None, validate=None: _FakeResponse(200, b"ok"))
    nodes = [
        {"id": "trigger", "node_type": "trigger.evidence_changed", "params": {}},
        {
            "id": "hook",
            "node_type": "action.webhook",
            "params": {"url": "https://hooks.example.com/{{trigger.output.trigger_kind}}"},
        },
    ]
    edges = [{"source": "trigger", "target": "hook"}]
    saved = wf.save_workflow(tmp_path, workflow_id=None, name="hook flow", description="", nodes=nodes, edges=edges)
    run = wf.run_workflow(tmp_path, workflow_id=saved["workflow_id"])

    assert run["result"] == "ok"
    by_id = {r["node_id"]: r for r in run["node_results"]}
    assert by_id["hook"]["result"] == "ok"
    assert by_id["hook"]["output"]["ok"] is True
    # {{node.output.*}} templating still flows into the webhook url.
    assert by_id["hook"]["params"]["url"] == "https://hooks.example.com/evidence_changed"
