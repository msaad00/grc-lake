"""Hosted API replicas survive slow startup and bounded voluntary disruptions."""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")


def render(*settings):
    command = ["helm", "template", "grc", str(ROOT / "deploy/helm/grc-lake")]
    for setting in settings:
        command += ["--set", setting]
    return subprocess.run(command, capture_output=True, text=True)


def documents(*settings):
    result = render(*settings)
    assert result.returncode == 0, result.stderr
    return {d["kind"]: d for d in yaml.safe_load_all(result.stdout) if d}


def test_http_startup_probe_delays_liveness_without_waiting_on_external_dependencies():
    docs = documents()
    pod = docs["Deployment"]["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert container["startupProbe"]["httpGet"] == {"path": "/api/healthz", "port": "http"}
    assert container["startupProbe"]["failureThreshold"] * container["startupProbe"]["periodSeconds"] == 300
    assert container["readinessProbe"]["httpGet"]["path"] == "/api/readyz"
    assert pod["terminationGracePeriodSeconds"] == 60
    assert "PodDisruptionBudget" not in docs


DISTRIBUTED = (
    "distributed.enabled=true",
    "distributed.clusterId=cluster",
    "distributed.bucket=test-bucket",
    "distributed.databaseSecretName=database",
    "replicaCount=2",
    "scheduler.enabled=false",
    "env[0].name=GRC_LAKE_COOKIE_SIGNING_KEY",
    "env[0].value=synthetic-test-secret",
)


@pytest.mark.parametrize("role", ["api", "reader"])
def test_distributed_http_budget_matches_only_its_replica_selector(role):
    docs = documents(*DISTRIBUTED, f"distributed.role={role}")
    budget = docs["PodDisruptionBudget"]
    assert budget["apiVersion"] == "policy/v1"
    assert budget["spec"]["maxUnavailable"] == 1
    assert budget["spec"]["selector"] == docs["Deployment"]["spec"]["selector"]


def test_workers_do_not_get_http_probe_or_api_disruption_budget():
    docs = documents(*DISTRIBUTED, "distributed.role=worker")
    container = docs["Deployment"]["spec"]["template"]["spec"]["containers"][0]
    assert "startupProbe" not in container
    assert "PodDisruptionBudget" not in docs


def test_operators_can_disable_startup_and_budget():
    docs = documents(*DISTRIBUTED, "probes.startup.enabled=false", "disruptionBudget.enabled=false")
    assert "startupProbe" not in docs["Deployment"]["spec"]["template"]["spec"]["containers"][0]
    assert "PodDisruptionBudget" not in docs


def test_single_distributed_replica_does_not_block_node_drain():
    assert "PodDisruptionBudget" not in documents(*DISTRIBUTED, "replicaCount=1")
