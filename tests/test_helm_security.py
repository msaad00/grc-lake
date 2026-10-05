"""Helm chart security guards for auth and HA."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")

CHART = Path(__file__).resolve().parents[1] / "deploy" / "helm" / "trustops"


def _helm_template(extra_sets: list[str] | None = None) -> subprocess.CompletedProcess[str]:
    cmd = ["helm", "template", "trustops", str(CHART)]
    for item in extra_sets or []:
        cmd.extend(["--set", item])
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def test_insecure_no_auth_requires_acknowledged_override() -> None:
    result = _helm_template(["security.allowInsecureNoAuth=true"])
    assert result.returncode != 0
    assert "allowInsecureOverride=acknowledged" in result.stderr


def test_insecure_no_auth_passes_with_acknowledged_override() -> None:
    result = _helm_template(
        [
            "security.allowInsecureNoAuth=true",
            "security.allowInsecureOverride=acknowledged",
        ]
    )
    assert result.returncode == 0
    assert "TRUSTOPS_ALLOW_INSECURE_NO_AUTH" in result.stdout


def test_ingress_requires_auth_configuration() -> None:
    result = _helm_template(["ingress.enabled=true"])
    assert result.returncode != 0
    assert "ingress.enabled requires authentication" in result.stderr


def test_ingress_passes_with_cookie_signing_key() -> None:
    result = _helm_template(
        [
            "ingress.enabled=true",
            "env[0].name=TRUSTOPS_COOKIE_SIGNING_KEY",
            "env[0].value=super-secret-for-tests",
        ]
    )
    assert result.returncode == 0


def test_ingress_passes_with_session_secret() -> None:
    result = _helm_template(
        [
            "ingress.enabled=true",
            "env[0].name=TRUSTOPS_SESSION_SECRET",
            "env[0].value=super-secret-for-tests",
        ]
    )
    assert result.returncode == 0


def test_multi_replica_rwo_lake_blocked_without_read_only() -> None:
    result = _helm_template(["replicaCount=2"])
    assert result.returncode != 0
    assert "replicaCount must be 1" in result.stderr


def test_read_only_lake_rejected_until_runtime_state_is_separate() -> None:
    result = _helm_template(["replicaCount=2", "lake.readOnly=true"])
    assert result.returncode != 0
    assert "read-only lake" in result.stderr


@pytest.mark.parametrize("access_mode", ["ReadWriteOnce", "ReadWriteMany", "ReadOnlyMany"])
def test_multiple_writers_rejected_independent_of_volume_mode(access_mode):
    result = _helm_template(["replicaCount=2", f"lake.persistence.accessMode={access_mode}"])
    assert result.returncode != 0


def test_rate_limit_redis_url_rendered_when_configured() -> None:
    result = _helm_template(["rateLimit.redisUrl=redis://redis:6379/0"])
    assert result.returncode == 0
    assert "TRUSTOPS_API_RATE_LIMIT_REDIS_URL" in result.stdout
    assert "redis://redis:6379/0" in result.stdout
    assert "TRUSTOPS_API_RATE_LIMIT_RPS" in result.stdout


def test_rollout_stops_previous_writer_before_starting_replacement() -> None:
    import yaml

    result = _helm_template()
    assert result.returncode == 0
    deployment = next(doc for doc in yaml.safe_load_all(result.stdout) if doc and doc["kind"] == "Deployment")
    assert deployment["spec"]["strategy"] == {"type": "Recreate"}


@pytest.mark.parametrize(
    "settings,expected",
    [
        ([], True),
        (["scheduler.allTenants=false"], False),
        (["security.allowInsecureNoAuth=true", "security.allowInsecureOverride=acknowledged"], False),
    ],
)
def test_scheduler_tenant_scope_matches_deployment(settings, expected):
    import yaml

    result = _helm_template(settings)
    assert result.returncode == 0
    cron = next(doc for doc in yaml.safe_load_all(result.stdout) if doc and doc["kind"] == "CronJob")
    args = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]["args"]
    assert ("--all-tenants" in args) is expected
