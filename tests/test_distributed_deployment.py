"""Distributed manifests use private scratch and explicit shared dependencies."""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")


@pytest.mark.parametrize("role", ["api", "reader", "worker"])
def test_distributed_profiles_use_two_replicas_without_shared_lake_volume(role):
    command = [
        "helm",
        "template",
        "cluster",
        str(ROOT / "deploy/helm/grc-lake"),
        "-f",
        str(ROOT / "deploy/examples/distributed/api-values.yaml"),
    ]
    if role != "api":
        command += ["-f", str(ROOT / f"deploy/examples/distributed/{role}-values.yaml")]
    command += ["--set", "scheduler.enabled=true"]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    docs = [d for d in yaml.safe_load_all(result.stdout) if d]
    assert not any(d["kind"] == "PersistentVolumeClaim" for d in docs)
    deployment = next(d for d in docs if d["kind"] == "Deployment")
    assert deployment["spec"]["replicas"] == 2
    assert deployment["spec"]["strategy"]["type"] == "RollingUpdate"
    spec = deployment["spec"]["template"]["spec"]
    assert next(v for v in spec["volumes"] if v["name"] == "lake")["emptyDir"]["sizeLimit"] == "20Gi"
    container = spec["containers"][0]
    env = {entry["name"]: entry for entry in container["env"]}
    assert env["GRC_LAKE_DEPLOYMENT_MODE"]["value"] == "distributed"
    assert env["GRC_LAKE_REPLICA_ROLE"]["value"] == role
    assert env["GRC_LAKE_DATABASE_URL"]["valueFrom"]["secretKeyRef"]["optional"] is False
    if role == "worker":
        assert container["args"][:3] == ["grc-lake", "cluster", "worker"]
        assert "livenessProbe" not in container and "readinessProbe" not in container
        assert not any(d["kind"] == "Service" for d in docs)
    scheduler = next(d for d in docs if d["kind"] == "CronJob")["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    assert "affinity" not in scheduler
    assert next(v for v in scheduler["volumes"] if v["name"] == "lake")["emptyDir"]["sizeLimit"] == "20Gi"


def test_cluster_env_cannot_override_rendered_storage_mode():
    result = subprocess.run(
        [
            "helm",
            "template",
            "cluster",
            str(ROOT / "deploy/helm/grc-lake"),
            "-f",
            str(ROOT / "deploy/examples/distributed/api-values.yaml"),
            "--set",
            "env[1].name=GRC_LAKE_DEPLOYMENT_MODE",
            "--set",
            "env[1].value=local",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "not env[]" in result.stderr
