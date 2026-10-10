"""Helm chart security guards for auth and HA."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")

CHART = Path(__file__).resolve().parents[1] / "deploy" / "helm" / "grc-lake"


TEST_SIGNING_KEY = ["env[0].name=GRC_LAKE_COOKIE_SIGNING_KEY", "env[0].value=test-only-signing-key"]


def _helm_template(
    extra_sets: list[str] | None = None, *, signing_key: bool = True
) -> subprocess.CompletedProcess[str]:
    """Render the chart; adds a test signing key unless the caller configures env[] itself."""
    sets = list(extra_sets or [])
    if signing_key and not any(item.startswith("env[") for item in sets):
        sets = [*TEST_SIGNING_KEY, *sets]
    cmd = ["helm", "template", "trustops", str(CHART)]
    for item in sets:
        cmd.extend(["--set", item])
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def test_default_values_fail_at_render_time_instead_of_crash_looping() -> None:
    result = _helm_template(signing_key=False)
    assert result.returncode != 0
    assert "GRC_LAKE_COOKIE_SIGNING_KEY" in result.stderr
    assert "allowInsecureNoAuth" in result.stderr


def test_lint_passes_with_the_documented_profile() -> None:
    profile = CHART.parents[1] / "examples" / "self-hosted-values.yaml"
    linted = subprocess.run(
        ["helm", "lint", str(CHART), "-f", str(profile)], capture_output=True, text=True, check=False
    )
    assert linted.returncode == 0, linted.stdout + linted.stderr


def test_writable_home_matches_the_image_user_home() -> None:
    import re

    dockerfile = (CHART.parents[2] / "Dockerfile").read_text()
    home = re.search(r"useradd [^\n]*--home (\S+)", dockerfile).group(1)
    workdir = re.findall(r"^WORKDIR (\S+)$", dockerfile, re.M)[-1]
    assert home == workdir == "/home/grc-lake"
    result = _helm_template()
    assert result.returncode == 0, result.stderr
    specs = _pod_specs(result.stdout)
    assert len(specs) == 2
    for spec in specs:
        container = spec["containers"][0]
        assert container["securityContext"]["readOnlyRootFilesystem"] is True
        mounts = {mount["name"]: mount["mountPath"] for mount in container["volumeMounts"]}
        assert mounts["home"] == home
        assert "emptyDir" in next(volume for volume in spec["volumes"] if volume["name"] == "home")
    deployment = next(spec for spec in specs if spec["containers"][0]["name"] != "scheduler")
    assert deployment["containers"][0]["name"] == "grc-lake"


def test_chart_metadata_follows_brand() -> None:
    import yaml

    chart = yaml.safe_load((CHART / "Chart.yaml").read_text())
    assert "Security Data Lake" not in chart["description"]
    assert "workbench" not in chart["description"].lower()
    assert "workbench" not in chart["keywords"]
    assert chart["icon"].endswith("/docs/images/grc-lake-mark.svg")
    assert (CHART.parents[2] / "docs" / "images" / "grc-lake-mark.svg").exists()


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
    assert "GRC_LAKE_ALLOW_INSECURE_NO_AUTH" in result.stdout


def test_ingress_requires_auth_configuration() -> None:
    result = _helm_template(["ingress.enabled=true"], signing_key=False)
    assert result.returncode != 0
    assert "ingress.enabled requires authentication" in result.stderr


def test_ingress_passes_with_cookie_signing_key() -> None:
    result = _helm_template(
        [
            "ingress.enabled=true",
            "env[0].name=GRC_LAKE_COOKIE_SIGNING_KEY",
            "env[0].value=super-secret-for-tests",
        ]
    )
    assert result.returncode == 0


def test_session_secret_alone_does_not_replace_cookie_signing_key() -> None:
    result = _helm_template(
        [
            "ingress.enabled=true",
            "env[0].name=GRC_LAKE_SESSION_SECRET",
            "env[0].value=super-secret-for-tests",
        ]
    )
    assert result.returncode != 0


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
    assert "GRC_LAKE_API_RATE_LIMIT_REDIS_URL" in result.stdout
    assert "redis://redis:6379/0" in result.stdout
    assert "GRC_LAKE_API_RATE_LIMIT_RPS" in result.stdout


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


@pytest.mark.parametrize("name", ["GRC_LAKE_OIDC_CLIENT_ID", "GRC_LAKE_SAML_IDP_METADATA_URL"])
def test_identity_provider_without_signing_secret_is_not_bootable(name):
    result = _helm_template(["ingress.enabled=true", f"env[0].name={name}", "env[0].value=idp-example"])
    assert result.returncode != 0
    assert "signing" in result.stderr


@pytest.mark.parametrize(
    "source", ["value=", "valueFrom.secretKeyRef.name=", "valueFrom.fieldRef.fieldPath=metadata.name"]
)
def test_empty_or_nonsecret_signing_configuration_is_rejected(source):
    result = _helm_template(
        ["security.requireAuthentication=true", "env[0].name=GRC_LAKE_COOKIE_SIGNING_KEY", f"env[0].{source}"]
    )
    assert result.returncode != 0
    assert "signing" in result.stderr


def test_secret_reference_renders_for_application_and_scheduler():
    import yaml

    result = _helm_template(
        [
            "security.requireAuthentication=true",
            "ingress.enabled=true",
            "env[0].name=GRC_LAKE_COOKIE_SIGNING_KEY",
            "env[0].valueFrom.secretKeyRef.name=trustops-server",
            "env[0].valueFrom.secretKeyRef.key=GRC_LAKE_COOKIE_SIGNING_KEY",
        ]
    )
    assert result.returncode == 0, result.stderr
    documents = {doc["kind"]: doc for doc in yaml.safe_load_all(result.stdout) if doc}
    for spec in (
        documents["Deployment"]["spec"]["template"]["spec"],
        documents["CronJob"]["spec"]["jobTemplate"]["spec"]["template"]["spec"],
    ):
        secret = next(item for item in spec["containers"][0]["env"] if item["name"] == "GRC_LAKE_COOKIE_SIGNING_KEY")
        assert secret["valueFrom"]["secretKeyRef"] == {"name": "trustops-server", "key": "GRC_LAKE_COOKIE_SIGNING_KEY"}


def test_scheduler_launches_cli_under_the_image_tini_entrypoint():
    import json

    import yaml

    result = _helm_template()
    assert result.returncode == 0, result.stderr
    cron = next(doc for doc in yaml.safe_load_all(result.stdout) if doc and doc["kind"] == "CronJob")
    container = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]
    dockerfile = (CHART.parents[2] / "Dockerfile").read_text()
    entrypoint = json.loads(
        next(line.removeprefix("ENTRYPOINT ") for line in dockerfile.splitlines() if line.startswith("ENTRYPOINT "))
    )
    assert entrypoint == ["/usr/bin/tini", "--"]
    # Kubernetes args replace Docker CMD, not ENTRYPOINT. tini must receive
    # the executable before the scheduler subcommand.
    assert container.get("command", container["args"])[0] == "grc-lake"


@pytest.mark.parametrize("with_session", [False, True])
def test_oidc_also_requires_its_separate_session_secret(with_session):
    settings = [
        "ingress.enabled=true",
        "env[0].name=GRC_LAKE_COOKIE_SIGNING_KEY",
        "env[0].value=test-cookie-key",
        "env[1].name=GRC_LAKE_OIDC_CLIENT_ID",
        "env[1].value=test-client",
        "env[2].name=GRC_LAKE_OIDC_ISSUER",
        "env[2].value=https://idp.example.com",
        "env[3].name=GRC_LAKE_OIDC_CLIENT_SECRET",
        "env[3].value=test-client-secret",
    ]
    if with_session:
        settings += ["env[4].name=GRC_LAKE_SESSION_SECRET", "env[4].value=test-oauth-key"]
    result = _helm_template(settings)
    assert (result.returncode == 0) is with_session


def test_env_cannot_bypass_explicit_no_auth_guard():
    result = _helm_template(
        [
            "security.requireAuthentication=true",
            "env[0].name=GRC_LAKE_COOKIE_SIGNING_KEY",
            "env[0].value=test-cookie-key",
            "env[1].name=GRC_LAKE_ALLOW_INSECURE_NO_AUTH",
            "env[1].value=1",
        ]
    )
    assert result.returncode != 0
    assert "security.allowInsecureNoAuth" in result.stderr


def _pod_specs(manifest: str) -> list[dict]:
    import yaml

    specs = []
    for doc in yaml.safe_load_all(manifest):
        if not doc:
            continue
        if doc["kind"] == "Deployment":
            specs.append(doc["spec"]["template"]["spec"])
        elif doc["kind"] == "CronJob":
            specs.append(doc["spec"]["jobTemplate"]["spec"]["template"]["spec"])
    return specs


def test_pods_do_not_mount_the_service_account_token_by_default() -> None:
    result = _helm_template()
    assert result.returncode == 0, result.stderr
    specs = _pod_specs(result.stdout)
    assert specs
    assert all(spec.get("automountServiceAccountToken") is False for spec in specs)


def test_in_cluster_kubernetes_connector_can_opt_in_to_the_token() -> None:
    result = _helm_template(["serviceAccount.automountToken=true"])
    assert result.returncode == 0, result.stderr
    assert all(spec.get("automountServiceAccountToken") is True for spec in _pod_specs(result.stdout))


def test_legacy_cookie_secret_still_satisfies_auth_guard() -> None:
    result = _helm_template(
        [
            "security.requireAuthentication=true",
            "env[0].name=TRUSTOPS_COOKIE_SIGNING_KEY",
            "env[0].value=test-only-signing-key",
        ]
    )
    assert result.returncode == 0


def test_empty_new_secret_cannot_fall_back_to_legacy_secret() -> None:
    result = _helm_template(
        [
            "security.requireAuthentication=true",
            "env[0].name=TRUSTOPS_COOKIE_SIGNING_KEY",
            "env[0].value=test-only-signing-key",
            "env[1].name=GRC_LAKE_COOKIE_SIGNING_KEY",
            "env[1].value=",
        ]
    )
    assert result.returncode != 0


def test_legacy_no_auth_env_cannot_bypass_acknowledgement() -> None:
    result = _helm_template(
        [
            "env[0].name=TRUSTOPS_ALLOW_INSECURE_NO_AUTH",
            "env[0].value=true",
        ]
    )
    assert result.returncode != 0
