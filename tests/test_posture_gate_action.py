"""Tests for the GRC Lake GitHub Action posture gate script."""

from __future__ import annotations

import os
import subprocess
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import yaml

from test_api_v1 import _Handler, _seed_lake


def _action_dir() -> Path:
    return Path(__file__).resolve().parents[1] / ".github" / "actions" / "posture-gate"


def _spin(lake: Path) -> ThreadingHTTPServer:
    _seed_lake(lake)

    class Handler(_Handler):
        lake_dir = lake
        dashboard_path = lake / "console.html"
        web_dist = None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _run_gate(
    lake: Path,
    *,
    min_score: str = "0",
    max_critical: str = "0",
    max_open: str = "-1",
    max_failing: str = "-1",
    allowed_failing: str = "",
    correlation_id: str = "test-corr-1",
) -> subprocess.CompletedProcess[str]:
    server = _spin(lake)
    host, port = server.server_address
    env = {
        **os.environ,
        "GRC_LAKE_URL": f"http://{host}:{port}",
        "GRC_LAKE_API_TOKEN": "",
        "CORRELATION_ID": correlation_id,
        "MIN_SCORE": min_score,
        "MAX_CRITICAL_VIOLATIONS": max_critical,
        "MAX_OPEN_VIOLATIONS": max_open,
        "MAX_FAILING_CONTROL_TESTS": max_failing,
        "ALLOWED_FAILING_CONTROLS": allowed_failing,
        "FAIL_ON_STALE_EVIDENCE": "false",
    }
    try:
        return subprocess.run(
            ["bash", str(_action_dir() / "posture-gate.sh")],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
    finally:
        server.shutdown()


def test_posture_gate_action_metadata_is_valid() -> None:
    action = yaml.safe_load((_action_dir() / "action.yml").read_text(encoding="utf-8"))
    assert action["name"] == "GRC Lake Posture Gate"
    assert "trustops-url" in action["inputs"]
    assert "max-failing-control-tests" in action["inputs"]
    assert action["runs"]["using"] == "composite"


def test_posture_gate_passes_against_seeded_lake(tmp_path: Path) -> None:
    result = _run_gate(tmp_path, min_score="0", max_critical="0", max_failing="-1")
    assert result.returncode == 0, result.stderr or result.stdout
    assert "Posture gate passed" in result.stdout
    assert "test-corr-1" in result.stdout


def test_posture_gate_fails_when_min_score_too_high(tmp_path: Path) -> None:
    result = _run_gate(tmp_path, min_score="100", max_failing="-1")
    assert result.returncode == 1
    assert "below minimum" in result.stdout


def test_posture_gate_fails_on_control_regression(tmp_path: Path) -> None:
    result = _run_gate(tmp_path, max_failing="0")
    assert result.returncode == 1
    assert "failing control tests" in result.stdout
    assert "SOC2-CC6.1" in result.stdout


def test_posture_gate_passes_with_allowed_failing_control(tmp_path: Path) -> None:
    result = _run_gate(
        tmp_path,
        max_failing="0",
        allowed_failing="SOC2-CC6.1",
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "Posture gate passed" in result.stdout


def test_tools_ci_wrapper_invokes_action_script(tmp_path: Path) -> None:
    wrapper = Path(__file__).resolve().parents[1] / "tools" / "ci" / "posture-gate.sh"
    assert wrapper.is_file()
    result = _run_gate(tmp_path, max_failing="-1")
    assert result.returncode == 0


def _run_gate_against_stub(
    *,
    failed_count: int,
    control_ids: list[str] | None,
    allowed_failing: str,
    max_failing: str = "0",
) -> subprocess.CompletedProcess[str]:
    """Run the gate against a stub API; ``control_ids=None`` makes /control-tests return 500."""
    import json
    from http.server import BaseHTTPRequestHandler

    posture = {
        "data": {
            "posture": {
                "score": 90,
                "state": "ok",
                "open_violation_count": 0,
                "critical_violation_count": 0,
                "failed_control_test_count": failed_count,
            }
        }
    }

    class Stub(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return None

        def do_GET(self) -> None:
            if self.path.startswith("/api/v1/posture/current"):
                body, code = json.dumps(posture).encode(), 200
            elif self.path.startswith("/api/v1/control-tests"):
                if control_ids is None:
                    body, code = b'{"errors":[{"detail":"boom"}]}', 500
                else:
                    body, code = json.dumps({"data": [{"control_id": c} for c in control_ids]}).encode(), 200
            else:
                body, code = b"{}", 404
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    env = {
        **os.environ,
        "GRC_LAKE_URL": f"http://{host}:{port}",
        "GRC_LAKE_API_TOKEN": "",
        "CORRELATION_ID": "",
        "MIN_SCORE": "0",
        "MAX_CRITICAL_VIOLATIONS": "0",
        "MAX_OPEN_VIOLATIONS": "-1",
        "MAX_FAILING_CONTROL_TESTS": max_failing,
        "ALLOWED_FAILING_CONTROLS": allowed_failing,
        "FAIL_ON_STALE_EVIDENCE": "false",
    }
    try:
        return subprocess.run(
            ["bash", str(_action_dir() / "posture-gate.sh")],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
    finally:
        server.shutdown()


def test_posture_gate_fails_closed_when_control_tests_request_fails() -> None:
    result = _run_gate_against_stub(failed_count=3, control_ids=None, allowed_failing="SOC2-CC6.1")
    assert result.returncode == 1, result.stdout
    assert "/api/v1/control-tests" in result.stdout
    assert "unbound variable" not in result.stderr


def test_posture_gate_allowlist_with_zero_failures_passes_on_any_bash() -> None:
    result = _run_gate_against_stub(failed_count=0, control_ids=[], allowed_failing="SOC2-CC6.1")
    assert result.returncode == 0, result.stderr or result.stdout
    assert "unbound variable" not in result.stderr


def test_posture_gate_counts_failures_beyond_the_fetched_page_as_unexpected() -> None:
    # 60 tests fail but the gate can only fetch 50 ids; all fetched ones are allowlisted.
    fetched = ["SOC2-CC6.1"] * 50
    result = _run_gate_against_stub(failed_count=60, control_ids=fetched, allowed_failing="SOC2-CC6.1")
    assert result.returncode == 1, result.stdout
