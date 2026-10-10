"""The artifact probe must fail on auth/isolation regressions, not just HTTP errors."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def probe():
    path = Path(__file__).resolve().parents[1] / "tools/authenticated_smoke.py"
    spec = importlib.util.spec_from_file_location("authenticated_smoke", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_unexpected_success_on_protected_route_fails(monkeypatch):
    module = probe()
    monkeypatch.setattr(module, "request", lambda *a, **kw: (200, {}, {}))
    with pytest.raises(AssertionError, match="expected 401"):
        module.expect("http://localhost", "GET", "/api/v1/controls", 401)


def test_other_tenant_marker_fails_even_when_own_marker_exists():
    module = probe()
    with pytest.raises(AssertionError, match="cross-tenant"):
        module.assert_isolated({"data": ["probe-alpha", "probe-beta"]}, "probe-alpha", "probe-beta")


def test_empty_evidence_cannot_pass_isolation():
    module = probe()
    with pytest.raises(AssertionError, match="own tenant"):
        module.assert_isolated({"data": []}, "probe-alpha", "probe-beta")


def test_failed_startup_cleans_secrets_and_disposable_volume(tmp_path, monkeypatch):
    module = probe()
    calls = []

    def run(*args, **kwargs):
        calls.append(args)
        if "up" in args:
            raise RuntimeError("startup failed")
        return "diagnostic"

    monkeypatch.setattr(module, "run", run)
    output = tmp_path / "receipt"
    with pytest.raises(RuntimeError, match="startup failed"):
        module.qualify("grc-lake:ci", output)
    assert any(c[-2:] == ("down", "--volumes") for c in calls)
    assert not (output / "grc-lake.env").exists()
    assert '"ok": false' in (output / "result.json").read_text()


def test_empty_seed_cannot_pass_authenticated_probe(monkeypatch):
    module = probe()
    monkeypatch.setattr(module, "request", lambda *a, **kw: (401, {}, {}))
    with pytest.raises(AssertionError, match="two distinct tenants"):
        module.exercise("http://localhost", [])


def test_cleanup_failure_preserves_primary_failure(tmp_path, monkeypatch):
    module = probe()

    def run(*args, **kwargs):
        if "up" in args:
            raise RuntimeError("startup failed")
        if "down" in args or "logs" in args:
            raise RuntimeError("daemon unavailable")
        return "diagnostic"

    monkeypatch.setattr(module, "run", run)
    output = tmp_path / "receipt"
    with pytest.raises(RuntimeError, match="startup failed"):
        module.qualify("grc-lake:ci", output)
    import json

    result = json.loads((output / "result.json").read_text())
    assert result["cleanup"] == "failed; remove this project when Docker is available"
    assert result["ok"] is False
    assert not (output / "grc-lake.env").exists()


def test_cleanup_cannot_target_either_operator_volume(tmp_path, monkeypatch):
    module = probe()

    def run(*args, **kwargs):
        if "up" in args:
            raise RuntimeError("stop before startup")
        return "diagnostic"

    monkeypatch.setattr(module, "run", run)
    output = tmp_path / "receipt"
    with pytest.raises(RuntimeError, match="stop before startup"):
        module.qualify("grc-lake:ci", output)
    import yaml

    overrides = yaml.safe_load((output / "override.yaml").read_text().replace("!override", ""))
    project = (output / "project-name.txt").read_text().strip()
    assert overrides["volumes"]["grc-lake-lake"]["name"] == project + "-server"
    assert overrides["volumes"]["grc-lake-demo-lake"]["name"] == project + "-demo"
