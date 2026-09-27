"""Kubernetes configuration-baseline connector tests (fixture-backed + fake API).

Fixtures are ``kubectl get -o json`` List documents whose items follow the
Kubernetes API reference (core/v1, apps/v1, batch/v1,
rbac.authorization.k8s.io/v1, networking.k8s.io/v1; docs v1.37). The fake API
mirrors the official Python client v36.0.3: ``list_*`` methods take ``limit``
and ``_continue`` and return a list whose serialized ``metadata.continue``
carries the next-page token; ``ApiException`` exposes ``status`` and
``headers``. CIS check numbers follow CIS Kubernetes Benchmark v1.10 as encoded
in aquasecurity/kube-bench ``cfg/cis-1.10``.
"""

from __future__ import annotations

import builtins
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import security_lakehouse.connector_runner as connector_runner
from security_lakehouse import connectors_kubernetes
from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.connector_state import append_config_event, latest_run
from security_lakehouse.connectors_kubernetes import (
    KubernetesClient,
    KubernetesFixtureClient,
    collect_kubernetes_evidence,
    parse_image,
    pod_security_findings,
)
from security_lakehouse.io import read_jsonl
from security_lakehouse.validation import validate_raw_events

FIXTURE = Path(__file__).parent / "fixtures" / "kubernetes"
CLUSTER = "prod-eks"
COLLECTED = datetime(2026, 9, 27, tzinfo=UTC)
ALLOWED = ["123456789012.dkr.ecr.us-east-1.amazonaws.com", "registry.k8s.io"]


def _rows(allowed: list[str] | None = ALLOWED, fixture: Path = FIXTURE) -> list[dict[str, Any]]:
    return collect_kubernetes_evidence(
        KubernetesFixtureClient(fixture, cluster_name=CLUSTER), allowed_registries=allowed, collected_at=COLLECTED
    )


def _event(rows: list[dict[str, Any]], object_ref: str, signal: str) -> dict[str, Any]:
    matches = [
        r
        for r in rows
        if r["entity"]["asset_id"] == f"kubernetes:{CLUSTER}:{object_ref}" and r["event_type"].endswith(f".{signal}")
    ]
    assert len(matches) == 1, (object_ref, signal, len(matches))
    return matches[0]


def test_collect_emits_valid_events_mapped_to_existing_controls() -> None:
    rows = _rows()

    assert validate_raw_events(rows) == []
    # 3 cluster-admin bindings + 4 namespaces + 6 workloads x 3 signals + 1 audit.
    assert len(rows) == 26
    catalog = load_control_catalog()
    for row in rows:
        assert row["source"] == "kubernetes"
        assert row["entity"]["org"] == CLUSTER
        assert row["controls"]
        assert all(control in catalog for control in row["controls"])
        assert row["evidence"]["evidence_ref"].startswith(("/api/", "/apis/"))


def test_every_control_constant_exists_in_the_catalog() -> None:
    catalog = load_control_catalog()
    for name in (
        "RBAC_CONTROLS",
        "POD_SECURITY_CONTROLS",
        "NETWORK_POLICY_CONTROLS",
        "IMAGE_REGISTRY_CONTROLS",
        "SECRET_ENV_CONTROLS",
        "AUDIT_LOGGING_CONTROLS",
    ):
        controls = getattr(connectors_kubernetes, name)
        assert controls and all(c in catalog for c in controls), name


def test_controller_owned_objects_are_not_double_counted() -> None:
    refs = {r["entity"]["asset_id"] for r in _rows()}
    assert f"kubernetes:{CLUSTER}:ReplicaSet:payments/api-7d9f8c6b5d" not in refs
    assert f"kubernetes:{CLUSTER}:Job:analytics/nightly-report-29312040" not in refs
    assert f"kubernetes:{CLUSTER}:Pod:payments/api-7d9f8c6b5d-x2k9p" not in refs
    assert f"kubernetes:{CLUSTER}:Pod:kube-system/kube-apiserver-cp-1" not in refs
    assert f"kubernetes:{CLUSTER}:Pod:default/debug" in refs
    assert f"kubernetes:{CLUSTER}:CronJob:analytics/nightly-report" in refs


@pytest.mark.parametrize(
    ("ref", "status", "severity"),
    [
        ("ClusterRoleBinding:cluster-admin", "observed", "info"),
        ("ClusterRoleBinding:platform-admins", "open", "high"),
        ("RoleBinding:payments/deployer-admin", "open", "high"),
    ],
)
def test_cluster_admin_bindings(ref: str, status: str, severity: str) -> None:
    event = _event(_rows(), ref, "cluster_admin_binding")
    assert (event["status"], event["severity"]) == (status, severity)


def test_non_cluster_admin_bindings_are_ignored() -> None:
    refs = {r["entity"]["asset_id"] for r in _rows()}
    assert f"kubernetes:{CLUSTER}:ClusterRoleBinding:auditors-view" not in refs
    assert f"kubernetes:{CLUSTER}:RoleBinding:analytics/analysts-edit" not in refs


@pytest.mark.parametrize(
    ("namespace", "status", "count"),
    [("payments", "pass", 2), ("analytics", "open", 0), ("default", "open", 0), ("kube-system", "open", 0)],
)
def test_network_policy_per_namespace(namespace: str, status: str, count: int) -> None:
    event = _event(_rows(), f"Namespace:{namespace}", "network_policy")
    assert event["status"] == status
    assert event["attributes"]["network_policy_count"] == count
    assert event["attributes"]["finding_reason"] == (None if status == "pass" else "no_network_policy")


@pytest.mark.parametrize(
    ("ref", "status", "severity", "reasons"),
    [
        ("Deployment:payments/api", "pass", "info", set()),
        # Container runAsUser 0 overrides the pod-level runAsNonRoot.
        ("Deployment:payments/legacy-worker", "open", "medium", {"runs_as_root"}),
        (
            "DaemonSet:kube-system/node-agent",
            "open",
            "high",
            {
                "privileged_container",
                "host_path_volume",
                "host_network",
                "host_pid",
                "run_as_non_root_not_enforced",
                "privilege_escalation_allowed",
            },
        ),
        # The init container is evaluated even though the main container is hardened.
        ("StatefulSet:analytics/warehouse", "open", "medium", {"run_as_non_root_not_enforced"}),
        ("CronJob:analytics/nightly-report", "pass", "info", set()),
        ("Pod:default/debug", "open", "medium", {"run_as_non_root_not_enforced", "privilege_escalation_allowed"}),
    ],
)
def test_pod_security(ref: str, status: str, severity: str, reasons: set[str]) -> None:
    event = _event(_rows(), ref, "pod_security")
    assert (event["status"], event["severity"]) == (status, severity)
    assert {f["reason"] for f in event["attributes"]["findings"]} == reasons


def test_init_container_finding_names_the_container() -> None:
    event = _event(_rows(), "StatefulSet:analytics/warehouse", "pod_security")
    assert event["attributes"]["findings"] == [{"reason": "run_as_non_root_not_enforced", "target": "fix-permissions"}]


def test_container_level_run_as_non_root_overrides_missing_pod_level() -> None:
    spec = {
        "containers": [
            {"name": "app", "securityContext": {"runAsNonRoot": True, "allowPrivilegeEscalation": False}},
        ]
    }
    assert pod_security_findings(spec) == []
    spec["securityContext"] = {"runAsNonRoot": True}
    spec["containers"][0]["securityContext"] = {"runAsNonRoot": False, "allowPrivilegeEscalation": False}
    assert [f["reason"] for f in pod_security_findings(spec)] == ["run_as_non_root_not_enforced"]


@pytest.mark.parametrize(
    ("image", "registry", "repository", "tag", "digest"),
    [
        ("nginx", "docker.io", "docker.io/library/nginx", None, None),
        ("busybox:1.36", "docker.io", "docker.io/library/busybox", "1.36", None),
        ("bitnami/redis:7.2", "docker.io", "docker.io/bitnami/redis", "7.2", None),
        ("index.docker.io/library/alpine:3", "docker.io", "docker.io/library/alpine", "3", None),
        ("localhost:5000/team/app:dev", "localhost:5000", "localhost:5000/team/app", "dev", None),
        ("ghcr.io/acme/warehouse:latest", "ghcr.io", "ghcr.io/acme/warehouse", "latest", None),
        ("registry.k8s.io/pause@sha256:abc", "registry.k8s.io", "registry.k8s.io/pause", None, "sha256:abc"),
        ("quay.io/org/app:1.0@sha256:def", "quay.io", "quay.io/org/app", "1.0", "sha256:def"),
    ],
)
def test_parse_image(image: str, registry: str, repository: str, tag: str | None, digest: str | None) -> None:
    parsed = parse_image(image)
    assert (parsed["registry"], parsed["repository"], parsed["tag"], parsed["digest"]) == (
        registry,
        repository,
        tag,
        digest,
    )


@pytest.mark.parametrize(
    ("ref", "status", "severity", "reason"),
    [
        ("Deployment:payments/api", "pass", "info", None),
        ("Deployment:payments/legacy-worker", "open", "medium", "registry_not_allowed"),
        ("DaemonSet:kube-system/node-agent", "pass", "info", None),
        ("StatefulSet:analytics/warehouse", "open", "medium", "registry_not_allowed"),
        ("Pod:default/debug", "open", "medium", "registry_not_allowed"),
    ],
)
def test_image_registry_with_allowlist(ref: str, status: str, severity: str, reason: str | None) -> None:
    event = _event(_rows(), ref, "image_registry")
    assert (event["status"], event["severity"], event["attributes"]["finding_reason"]) == (status, severity, reason)


@pytest.mark.parametrize(
    ("ref", "status", "severity", "reason"),
    [
        # Digest-pinned, no allowlist: inventory only, never a pass.
        ("Deployment:payments/api", "observed", "info", None),
        ("Deployment:payments/legacy-worker", "open", "low", "unpinned_image_tag"),
        ("StatefulSet:analytics/warehouse", "open", "low", "unpinned_image_tag"),
        ("Pod:default/debug", "observed", "info", None),
    ],
)
def test_image_registry_without_allowlist(ref: str, status: str, severity: str, reason: str | None) -> None:
    event = _event(_rows(allowed=None), ref, "image_registry")
    assert (event["status"], event["severity"], event["attributes"]["finding_reason"]) == (status, severity, reason)


def test_allowlist_matches_repository_prefixes_and_docker_hub_alias() -> None:
    event = _event(
        _rows(allowed=["docker.io/library", "GHCR.io/acme/", *ALLOWED]), "Pod:default/debug", "image_registry"
    )
    assert event["status"] == "pass"
    warehouse = _event(_rows(allowed=["ghcr.io/acme", *ALLOWED]), "StatefulSet:analytics/warehouse", "image_registry")
    assert warehouse["attributes"]["disallowed_registries"] == ["docker.io"]


@pytest.mark.parametrize(
    ("ref", "status"),
    [
        ("Deployment:payments/api", "open"),
        ("StatefulSet:analytics/warehouse", "open"),
        ("Deployment:payments/legacy-worker", "pass"),
        ("CronJob:analytics/nightly-report", "pass"),
    ],
)
def test_secret_env(ref: str, status: str) -> None:
    event = _event(_rows(), ref, "secret_env")
    assert event["status"] == status
    assert event["severity"] == ("low" if status == "open" else "info")


def test_secret_env_keeps_names_only() -> None:
    api = _event(_rows(), "Deployment:payments/api", "secret_env")["attributes"]
    assert api["secret_env_vars"] == ["api/DB_PASSWORD"]
    assert api["secret_env_from_count"] == 0
    blob = json.dumps(_rows())
    # Secret object names, literal env values, and non-audit command args are never stored.
    for needle in ("api-db", "warehouse-credentials", "structured-json", "chown", "LOG_LEVEL", "tls-private-key-file"):
        assert needle not in blob


def test_attributes_do_not_carry_annotations_or_labels() -> None:
    for row in _rows():
        assert not {"annotations", "labels", "env", "command", "args"} & set(row["attributes"])


def test_audit_logging_passes_when_policy_and_sink_flags_are_set() -> None:
    event = _event(_rows(), "Cluster:apiserver", "audit_logging")
    assert (event["status"], event["severity"]) == ("pass", "info")


class _StaticClient:
    def __init__(self, **lists: list[dict[str, Any]]) -> None:
        self.cluster_name = CLUSTER
        self._lists = lists

    def __getattr__(self, name: str) -> Any:
        return lambda: self._lists.get(name, [])


def test_audit_logging_open_when_policy_flag_missing() -> None:
    pod = {
        "metadata": {"name": "kube-apiserver-cp-1"},
        "spec": {"containers": [{"command": ["kube-apiserver", "--audit-log-path", "/var/log/audit.log"]}]},
    }
    rows = collect_kubernetes_evidence(_StaticClient(apiserver_pods=[pod]), collected_at=COLLECTED)  # type: ignore[arg-type]
    assert len(rows) == 1
    assert (rows[0]["status"], rows[0]["severity"]) == ("open", "high")
    assert rows[0]["attributes"]["finding_reason"] == "audit_logging_disabled"


def test_webhook_sink_counts_as_audit_logging() -> None:
    pod = {
        "metadata": {"name": "kube-apiserver-cp-1"},
        "spec": {
            "containers": [
                {
                    "command": ["kube-apiserver"],
                    "args": ["--audit-policy-file=/p.yaml", "--audit-webhook-config-file=/w"],
                }
            ]
        },
    }
    rows = collect_kubernetes_evidence(_StaticClient(apiserver_pods=[pod]), collected_at=COLLECTED)  # type: ignore[arg-type]
    assert rows[0]["status"] == "pass"


def test_managed_control_plane_emits_no_audit_event(tmp_path: Path) -> None:
    for name in ("namespaces.json", "workloads.json"):
        shutil.copy(FIXTURE / name, tmp_path / name)
    rows = _rows(fixture=tmp_path)
    assert rows
    assert not [r for r in rows if r["event_type"] == "kubernetes.cluster.audit_logging"]


def test_empty_cluster_emits_nothing(tmp_path: Path) -> None:
    assert _rows(fixture=tmp_path) == []


def test_long_names_keep_event_ids_unique_and_bounded() -> None:
    base = "a" * 120
    workloads = [
        {
            "kind": "Deployment",
            "metadata": {"name": f"{base}-{i}", "namespace": "ns"},
            "spec": {"template": {"spec": {"containers": [{"name": "c", "image": "registry.k8s.io/x:1"}]}}},
        }
        for i in range(2)
    ]
    rows = collect_kubernetes_evidence(_StaticClient(workloads=workloads), collected_at=COLLECTED)  # type: ignore[arg-type]
    assert validate_raw_events(rows) == []
    assert all(len(r["event_id"]) <= len("kubernetes-") + 96 for r in rows)


# --- Live client over a fake official-client API ----------------------------------


class _ApiException(Exception):
    def __init__(self, status: int, headers: dict[str, str] | None = None) -> None:
        super().__init__(status)
        self.status = status
        self.headers = headers or {}


class _FakeApi:
    def __init__(self, pages: dict[str, list[Any]]) -> None:
        self.pages = pages
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, method: str) -> Any:
        def call(**kwargs: Any) -> Any:
            self.calls.append((method, kwargs))
            queue = self.pages.get(method)
            if not queue:
                return {"metadata": {}, "items": []}
            item = queue.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        return call


def _live(pages: dict[str, list[Any]]) -> tuple[KubernetesClient, _FakeApi]:
    api = _FakeApi(pages)
    apis = {name: api for name in ("core", "rbac", "networking", "apps", "batch")}
    return KubernetesClient(CLUSTER, apis=apis), api


def test_live_client_follows_continue_tokens() -> None:
    namespaces = json.loads((FIXTURE / "namespaces.json").read_text())["items"]
    client, api = _live(
        {
            "list_namespace": [
                {"metadata": {"continue": "tok-1"}, "items": namespaces[:2]},
                {"metadata": {"continue": ""}, "items": namespaces[2:]},
            ]
        }
    )

    assert [n["metadata"]["name"] for n in client.namespaces()] == [n["metadata"]["name"] for n in namespaces]
    assert api.calls == [
        ("list_namespace", {"limit": connectors_kubernetes.PAGE_LIMIT}),
        ("list_namespace", {"limit": connectors_kubernetes.PAGE_LIMIT, "_continue": "tok-1"}),
    ]


def test_live_client_retries_429_honoring_retry_after(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr("time.sleep", sleeps.append)
    client, api = _live(
        {"list_cluster_role_binding": [_ApiException(429, {"Retry-After": "3"}), {"metadata": {}, "items": [{"a": 1}]}]}
    )

    assert client.cluster_role_bindings() == [{"a": 1}]
    assert sleeps == [3.0]
    assert len(api.calls) == 2


def test_live_client_does_not_retry_forbidden() -> None:
    client, api = _live({"list_cluster_role_binding": [_ApiException(403)]})

    with pytest.raises(_ApiException):
        client.cluster_role_bindings()
    assert len(api.calls) == 1


def test_live_client_adds_kind_to_workloads_and_scopes_apiserver_lookup() -> None:
    deployment = {"metadata": {"name": "api", "namespace": "payments"}, "spec": {}}
    client, api = _live({"list_deployment_for_all_namespaces": [{"metadata": {}, "items": [deployment]}]})

    workloads = client.workloads()
    assert workloads[0]["kind"] == "Deployment"
    assert workloads[0]["apiVersion"] == "apps/v1"
    client.apiserver_pods()
    assert api.calls[-1] == (
        "list_namespaced_pod",
        {"namespace": "kube-system", "label_selector": "component=kube-apiserver", "limit": 500},
    )
    # Only list verbs are ever called.
    assert all(method.startswith("list_") for method, _ in api.calls)


def test_missing_kubernetes_package_explains_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "kubernetes" or name.startswith("kubernetes."):
            raise ImportError("No module named 'kubernetes'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(RuntimeError, match=r"kubernetes extra.*--fixture-dir"):
        KubernetesClient(CLUSTER)


# --- Runner wiring (depends on the kubernetes-cluster registry entry) ---------------


def test_sync_requires_cluster_name_for_live_collection(tmp_path: Path) -> None:
    append_config_event(tmp_path, connector_id="kubernetes-cluster", state="enabled", actor="alice")

    with pytest.raises(connector_runner.ConnectorSyncError, match="cluster_name"):
        connector_runner.run_connector_sync(tmp_path, connector_id="kubernetes-cluster")
    assert latest_run(tmp_path, "kubernetes-cluster", kind="sync")["result"] == "error"


def test_fixture_sync_materializes_kubernetes_evidence(tmp_path: Path) -> None:
    append_config_event(
        tmp_path,
        connector_id="kubernetes-cluster",
        state="enabled",
        actor="alice",
        credentials={"cluster_name": CLUSTER, "allowed_registries": ",".join(ALLOWED)},
    )

    result = connector_runner.run_connector_sync(tmp_path, connector_id="kubernetes-cluster", fixture_dir=FIXTURE)

    assert result.result == "ok"
    assert result.evidence_count == 26
    raw_rows = read_jsonl(tmp_path / connector_runner.CONNECTOR_RAW_FILE)
    assert validate_raw_events(raw_rows) == []
    assert {r["entity"]["org"] for r in raw_rows} == {CLUSTER}
    debug = [
        r
        for r in raw_rows
        if r["event_type"] == "kubernetes.workload.image_registry" and r["entity"]["asset_id"].endswith("default/debug")
    ]
    assert debug[0]["attributes"]["allowlist_configured"] is True
