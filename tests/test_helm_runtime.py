"""Rendered deployment examples must agree with the real server startup contract."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")


@pytest.mark.parametrize("profile", ["self-hosted-values.yaml", "aws-snowflake-poc-values.yaml"])
def test_published_profiles_boot_authenticated_server(profile, monkeypatch, tmp_path):
    from security_lakehouse.server_app import create_app

    rendered = subprocess.run(
        [
            "helm",
            "template",
            "trustops",
            str(ROOT / "deploy/helm/grc-lake"),
            "-f",
            str(ROOT / "deploy/examples" / profile),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    documents = {doc["kind"]: doc for doc in yaml.safe_load_all(rendered.stdout) if doc}
    container = documents["Deployment"]["spec"]["template"]["spec"]["containers"][0]
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    assert container["image"] == f"ghcr.io/koda-ai-studio/grc-lake:{version}"
    for key in os.environ:
        if key.startswith("GRC_LAKE_"):
            monkeypatch.delenv(key)
    for item in container["env"]:
        if item["name"] == "GRC_LAKE_LAKE":
            continue
        # The chart references customer Secrets. Resolve only synthetic values
        # here; this exercises server configuration, never a cloud connection.
        monkeypatch.setenv(item["name"], str(item.get("value", "synthetic-deployment-secret")))
    app = create_app(tmp_path / "lake", require_auth=True)
    assert app.state.require_auth is True
    assert (app.state.oidc_config is not None) is (profile == "aws-snowflake-poc-values.yaml")
    monkeypatch.delenv("GRC_LAKE_COOKIE_SIGNING_KEY")
    with pytest.raises(RuntimeError, match="GRC_LAKE_COOKIE_SIGNING_KEY"):
        create_app(tmp_path / "missing-secret", require_auth=True)

    scheduler = documents["CronJob"]["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]
    assert scheduler["image"] == container["image"]
    argv = scheduler["args"]
    assert argv[:3] == ["grc-lake", "scheduler", "tick"]
    result = subprocess.run(
        [sys.executable, "-m", "security_lakehouse.cli", *argv[1:], "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "--all-tenants" in result.stdout
