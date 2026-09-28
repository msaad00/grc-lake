"""GCP cloud-posture evidence collector.

A cloud-posture connector mirroring ``connectors_aws``. It collects read-only
GCP project posture signals — IAM role bindings on the project policy,
org/project policy constraints, and a Cloud Asset Inventory snapshot — and
emits them in the lake's raw evidence shape so they flow through the same
validate -> write -> pipeline path the ``github-security`` / ``okta-identity`` /
``aws-posture`` runners use.

Two clients sit behind one interface, mirroring ``connectors_aws``:

* :class:`GCPClient` — authenticated, read-only reads via the Google Cloud
  client libraries (Resource Manager, IAM, Cloud Asset Inventory). The Google
  client imports are lazy (inside the client) so the base/test install never
  needs them; CI runs entirely off fixtures.
* :class:`GCPFixtureClient` — reads ``iam_bindings.json`` / ``org_policies.json``
  / ``assets.json`` from a fixture directory so collection is fully testable
  without live GCP credentials.

The collector is strictly read-only and least-privilege: it only ever issues
``GetIamPolicy`` / ``ListOrgPolicies`` / ``ListAssets`` style reads and never
mutates GCP state.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.connector_errors import (
    CollectionGapError,
    ConnectorAccessError,
    ConnectorConfigError,
)
from security_lakehouse.connector_ids import stable_id_slug
from security_lakehouse.identity import classify_identity_type
from security_lakehouse.io import read_json
from security_lakehouse.models import utc_iso

# Cloud/config controls that exist in controls/catalog.json. Verified before
# wiring (SOC2-CC6.1 logical access, ISO27001-A.5.15 access control,
# HIPAA-164.308(a)(4) access management).
IAM_CONTROLS = ["SOC2-CC6.1", "ISO27001-A.5.15", "HIPAA-164.308(a)(4)"]
POLICY_CONTROLS = ["SOC2-CC6.1", "ISO27001-A.5.15"]
ASSET_CONTROLS = ["SOC2-CC6.1"]

# GCP roles that grant broad, project-wide privilege. A binding to one of these
# is the noteworthy access signal an auditor should review.
PRIVILEGED_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/resourcemanager.organizationAdmin",
}

# Org-policy constraints whose enforcement we expect to be on. An unenforced
# constraint is an open config finding worth surfacing.
EXPECTED_ENFORCED_CONSTRAINTS = {
    "constraints/iam.disableServiceAccountKeyCreation",
    "constraints/compute.requireOsLogin",
}


# Each sub-collection, the API that serves it, and the IAM permission it needs.
# A disabled API or denied permission becomes a coverage gap for that
# sub-collection instead of failing the whole sync.
@dataclass(frozen=True)
class _Collection:
    key: str
    label: str
    api_label: str
    api: str
    permission: str


IAM_COLLECTION = _Collection(
    "iam_bindings",
    "project IAM bindings",
    "Cloud Resource Manager API",
    "cloudresourcemanager.googleapis.com",
    "resourcemanager.projects.getIamPolicy",
)
ORG_POLICY_COLLECTION = _Collection(
    "org_policies",
    "organization policies",
    "Org Policy API",
    "orgpolicy.googleapis.com",
    "orgpolicy.policies.list",
)
ASSET_COLLECTION = _Collection(
    "assets",
    "asset inventory",
    "Cloud Asset API",
    "cloudasset.googleapis.com",
    "cloudasset.assets.listResource",
)
_READ_FAILED = {
    "iam_bindings": "GCP collection incomplete: project IAM policy read failed",
    "org_policies": "GCP collection incomplete: organization policy read failed",
    "assets": "GCP collection incomplete: asset inventory read failed",
}
_SERVICE_NAME = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)*\.googleapis\.com$")
_PERMISSION_NAME = re.compile(r"^[a-z][a-zA-Z0-9]*(\.[a-zA-Z0-9]+){2,}$")
_PERMISSION_IN_MESSAGE = re.compile(r"[Pp]ermission '([a-z][a-zA-Z0-9]*(?:\.[a-zA-Z0-9]+){2,})'")
_ADC_MISSING = (
    "GCP Application Default Credentials were not found; run "
    "'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS"
)


def _collection_error(exc: Exception, collection: _Collection, project_id: str) -> ConnectorAccessError:
    """Map a Google client failure to an operator-safe error.

    Classification is duck-typed on ``google.api_core`` ``GoogleAPICallError``
    (``reason`` / ``metadata`` from the ``google.rpc.ErrorInfo`` detail, plus the
    HTTP ``code``) so the base install needs no Google packages. Provider text is
    never copied into the message; only a validated API or permission name is.
    """
    if type(exc).__name__ == "DefaultCredentialsError":
        return ConnectorAccessError(_ADC_MISSING)
    reason = str(getattr(exc, "reason", "") or "")
    raw_metadata = getattr(exc, "metadata", None)
    # ErrorInfo metadata is a protobuf map (a Mapping, not a dict).
    metadata = {str(k): str(v) for k, v in raw_metadata.items()} if isinstance(raw_metadata, Mapping) else {}
    message = str(getattr(exc, "message", "") or exc)
    code = getattr(exc, "code", None)
    project = _project_slug(project_id)
    not_collected = f"{collection.label} {'were' if collection.label.endswith('s') else 'was'} not collected"
    if reason == "SERVICE_DISABLED" or "has not been used in project" in message or "it is disabled" in message:
        service = metadata.get("service", "")
        api = service if _SERVICE_NAME.match(service) else collection.api
        label = collection.api_label if api == collection.api else api
        return CollectionGapError(
            f"{label} ({api}) is not enabled on project {project}; {not_collected}",
            collection=collection.key,
            reason="api_disabled",
            api=api,
        )
    if reason == "IAM_PERMISSION_DENIED" or type(exc).__name__ in {"PermissionDenied", "Forbidden"} or code == 403:
        permission = metadata.get("permission", "")
        if not _PERMISSION_NAME.match(permission):
            found = _PERMISSION_IN_MESSAGE.search(message)
            permission = found.group(1) if found else collection.permission
        return CollectionGapError(
            f"permission {permission} denied on project {project}; {not_collected}",
            collection=collection.key,
            reason="permission_denied",
            api=None,
            permission=permission,
        )
    return ConnectorAccessError(_READ_FAILED[collection.key])


class GCPClient:
    """Authenticated, read-only GCP posture client.

    The Google Cloud client libraries are imported lazily so installs that
    never touch live GCP do not need them. Credentials resolve through Google's
    Application Default Credentials chain (``GOOGLE_APPLICATION_CREDENTIALS`` /
    workload identity / metadata server).
    """

    def __init__(self, project_id: str) -> None:
        self.project_id = project_id
        try:
            from google.cloud import (  # noqa: PLC0415
                asset_v1,
                resourcemanager_v3,
            )
        except ImportError as exc:  # pragma: no cover - exercised only with live GCP
            raise ConnectorConfigError(
                "gcp-posture live collection requires google-cloud-resource-manager and "
                "google-cloud-asset; install the cloud extra or use --fixture-dir"
            ) from exc
        self._projects = resourcemanager_v3.ProjectsClient()
        self._assets = asset_v1.AssetServiceClient()
        # Org Policy lives in the separate google-cloud-org-policy distribution
        # (google.cloud.orgpolicy_v2), not resourcemanager_v3. Missing support
        # is reported as a coverage gap so the incomplete scope stays visible.
        self._org_policies: Any | None = None
        try:
            from google.cloud import orgpolicy_v2  # noqa: PLC0415

            self._org_policies = orgpolicy_v2.OrgPolicyClient()
        except ImportError:  # pragma: no cover - optional dependency
            self._org_policies = None

    def iam_bindings(self) -> list[dict[str, Any]]:
        try:
            policy = self._projects.get_iam_policy(resource=f"projects/{self.project_id}")
        except Exception as exc:  # noqa: BLE001 - classified into an operator-safe error
            raise _collection_error(exc, IAM_COLLECTION, self.project_id) from None
        bindings: list[dict[str, Any]] = []
        for binding in getattr(policy, "bindings", []):
            bindings.append(
                {
                    "role": getattr(binding, "role", ""),
                    "members": list(getattr(binding, "members", [])),
                }
            )
        return bindings

    def org_policies(self) -> list[dict[str, Any]]:
        if self._org_policies is None:
            raise CollectionGapError(
                "google-cloud-org-policy is not installed; organization policies were not collected",
                collection=ORG_POLICY_COLLECTION.key,
                reason="client_unavailable",
            )
        policies: list[dict[str, Any]] = []
        try:
            listing = self._org_policies.list_policies(parent=f"projects/{self.project_id}")
            for policy in listing:
                spec = getattr(policy, "spec", None)
                rules = getattr(spec, "rules", []) if spec is not None else []
                enforced = any(bool(getattr(rule, "enforce", False)) for rule in rules)
                policies.append(
                    {
                        "name": getattr(policy, "name", ""),
                        "constraint": getattr(policy, "name", "").split("/policies/")[-1],
                        "enforced": enforced,
                    }
                )
        except Exception as exc:  # noqa: BLE001 - provider details must not enter stored errors
            raise _collection_error(exc, ORG_POLICY_COLLECTION, self.project_id) from None
        return policies

    def assets(self) -> list[dict[str, Any]]:
        assets: list[dict[str, Any]] = []
        try:
            listing = self._assets.list_assets(request={"parent": f"projects/{self.project_id}"})
            for asset in listing:
                assets.append(
                    {
                        "name": getattr(asset, "name", ""),
                        "asset_type": getattr(asset, "asset_type", ""),
                    }
                )
        except Exception as exc:  # noqa: BLE001 - provider details must not enter stored errors
            raise _collection_error(exc, ASSET_COLLECTION, self.project_id) from None
        return assets


class GCPFixtureClient:
    """Offline GCP posture client backed by a fixture directory."""

    def __init__(self, fixture_dir: str | Path, *, project_id: str = "fixture-project") -> None:
        self.fixture = Path(fixture_dir)
        self.project_id = project_id

    def iam_bindings(self) -> list[dict[str, Any]]:
        payload = self._read("iam_bindings.json")
        if isinstance(payload, dict):
            payload = payload.get("bindings", [])
        return [item for item in payload if isinstance(item, dict)]

    def org_policies(self) -> list[dict[str, Any]]:
        return self._read_list("org_policies.json")

    def assets(self) -> list[dict[str, Any]]:
        payload = self._read("assets.json")
        if isinstance(payload, dict):
            payload = payload.get("assets", [])
        return [item for item in payload if isinstance(item, dict)]

    def _read(self, name: str) -> Any:
        path = self.fixture / name
        return read_json(path) if path.exists() else []

    def _read_list(self, name: str) -> list[dict[str, Any]]:
        payload = self._read(name)
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        return []


def probe_gcp_access(*, credentials: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    """Prove live, read-only access to the configured project.

    Reads the project IAM policy (``resourcemanager.projects.getIamPolicy``),
    the one read every sync needs. Org Policy and Cloud Asset reads are optional
    at sync time (reported as coverage gaps), so the probe does not require them.
    """
    del options
    project_id = str(credentials.get("project_id") or "").strip()
    if not project_id:
        raise ConnectorConfigError("GCP probe requires project_id")
    try:
        client = GCPClient(project_id)
    except ConnectorConfigError:
        raise
    except Exception as exc:  # noqa: BLE001 - classified into an operator-safe error
        raise _collection_error(exc, IAM_COLLECTION, project_id) from None
    bindings = client.iam_bindings()
    return {
        "ok": True,
        "project_id": project_id,
        "capabilities": [IAM_COLLECTION.permission],
        "binding_count": len(bindings),
    }


def collect_gcp_evidence(
    client: GCPClient | GCPFixtureClient,
    *,
    project_id: str | None = None,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    """Collect normalized raw posture evidence from a GCP project.

    Emits, per collection:

    * one IAM role-binding event per role bound on the project policy
      (privileged role -> high open finding for review),
    * one org/project policy event per policy constraint (an unenforced
      expected constraint is an open config finding),
    * one asset-inventory event per discovered resource (-> asset control).

    Every event passes :func:`security_lakehouse.validation.validate_raw_events`.
    """
    now = collected_at or datetime.now(UTC)
    project = _project_slug(project_id or client.project_id)
    rows: list[dict[str, Any]] = []
    gaps: list[CollectionGapError] = []

    def read(method: Any) -> list[dict[str, Any]]:
        try:
            return list(method())
        except CollectionGapError as gap:
            gaps.append(gap)
            return []

    for binding in read(client.iam_bindings):
        role = str(binding.get("role") or "").strip()
        if not role:
            continue
        rows.append(_iam_event(project, binding, now, tenant_id))

    for policy in read(client.org_policies):
        constraint = str(policy.get("constraint") or policy.get("name") or "").strip()
        if not constraint:
            continue
        rows.append(_policy_event(project, policy, now, tenant_id))

    for asset in read(client.assets):
        name = str(asset.get("name") or "").strip()
        if not name:
            continue
        rows.append(_asset_event(project, asset, now, tenant_id))

    if len(gaps) == 3:
        raise ConnectorAccessError("GCP collection failed: " + "; ".join(gap.message for gap in gaps))
    rows.extend(_gap_event(project, gap, now, tenant_id) for gap in gaps)
    return rows


def _gap_event(project: str, gap: CollectionGapError, collected_at: datetime, tenant_id: str) -> dict[str, Any]:
    """A coverage-gap row: an actionable open item that neither passes nor fails a control."""
    return _event(
        project=project,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="collection_gap",
        dedupe_key=gap.collection,
        event_type="gcp.collection_gap",
        asset_id=f"gcp:project:{project}",
        asset_type="collection_scope",
        controls=[],
        status="open",
        severity="low",
        evidence_ref=f"gcp:{project}:collection-gap:{gap.collection}",
        attributes=gap.attributes(),
    )


def _iam_event(
    project: str,
    binding: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any]:
    role = str(binding["role"])
    members = sorted(str(m) for m in binding.get("members", []) if m)
    privileged = role in PRIVILEGED_ROLES
    # A binding can bind several members; classify each and collapse to a single
    # identity_type when they agree, otherwise mark the binding "mixed" (or
    # "unknown" when there are no members to classify).
    member_types = {classify_identity_type(member=m) for m in members}
    if not member_types:
        identity_type = "unknown"
    elif len(member_types) == 1:
        identity_type = member_types.pop()
    else:
        identity_type = "mixed"
    return _event(
        project=project,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="iam_binding",
        dedupe_key=role,
        event_type="gcp.cloud.iam_binding",
        asset_id=f"gcp:project:{project}:role/{role}",
        asset_type="iam_binding",
        controls=IAM_CONTROLS,
        # Privileged role bindings are the noteworthy ones for review.
        status="open" if privileged else "observed",
        severity="high" if privileged else "info",
        evidence_ref=f"//cloudresourcemanager.googleapis.com/projects/{project}:getIamPolicy",
        attributes={
            "role": role,
            "members": members,
            "member_count": len(members),
            "identity_type": identity_type,
            "privileged": privileged,
        },
    )


def _policy_event(
    project: str,
    policy: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any]:
    constraint = str(policy.get("constraint") or policy.get("name") or "")
    enforced = bool(policy.get("enforced"))
    expected = constraint in EXPECTED_ENFORCED_CONSTRAINTS
    # An expected-on constraint that is not enforced is the finding to raise.
    needs_enforcement = expected and not enforced
    return _event(
        project=project,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="org_policy",
        dedupe_key=constraint,
        event_type="gcp.cloud.org_policy",
        asset_id=f"gcp:project:{project}",
        asset_type="account_config",
        controls=POLICY_CONTROLS,
        status="open" if needs_enforcement else ("pass" if enforced else "observed"),
        severity="medium" if needs_enforcement else "info",
        evidence_ref=f"//orgpolicy.googleapis.com/projects/{project}/policies/{constraint}",
        attributes={
            "constraint": constraint,
            "enforced": enforced,
            "expected_enforced": expected,
            "needs_enforcement": needs_enforcement,
        },
    )


def _asset_event(
    project: str,
    asset: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any]:
    name = str(asset["name"])
    asset_type = str(asset.get("asset_type") or "unknown")
    return _event(
        project=project,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="asset",
        dedupe_key=name,
        event_type="gcp.cloud.asset",
        asset_id=f"gcp:asset:{name}",
        asset_type="cloud_resource",
        controls=ASSET_CONTROLS,
        status="observed",
        severity="info",
        evidence_ref=f"//cloudasset.googleapis.com/projects/{project}/assets/{name}",
        attributes={
            "asset_name": name,
            "asset_type": asset_type,
        },
    )


def _event(
    *,
    project: str,
    collected_at: datetime,
    tenant_id: str,
    signal: str,
    event_type: str,
    asset_id: str,
    asset_type: str,
    controls: list[str],
    status: str,
    severity: str,
    evidence_ref: str,
    attributes: dict[str, Any],
    dedupe_key: str | None = None,
) -> dict[str, Any]:
    stable = _stable_suffix(project=project, signal=signal, asset_id=asset_id, dedupe_key=dedupe_key)
    return {
        "event_id": f"gcp-{stable}",
        "tenant_id": tenant_id,
        "workspace_id": "default",
        "event_time": utc_iso(collected_at),
        "source": "gcp",
        "event_type": event_type,
        "entity": {
            "asset_id": asset_id,
            "asset_type": asset_type,
            "asset_owner": project,
            "environment": "prod",
            "org": project,
        },
        "severity": severity,
        "status": status,
        "controls": controls,
        "evidence": {
            "evidence_id": f"ev-{stable}",
            "evidence_ref": evidence_ref,
            "evidence_collected_at": utc_iso(collected_at),
        },
        "attributes": attributes,
    }


def _project_slug(project_id: str) -> str:
    slug = re.sub(r"[^a-z0-9_.:-]+", "-", str(project_id).lower()).strip("-")
    return slug or "gcp-project"


def _stable_suffix(*, project: str, signal: str, asset_id: str, dedupe_key: str | None) -> str:
    """Build a deterministic connector-local id without hashing identity data.

    The pipeline computes the canonical raw evidence hash after collection. These
    IDs only need to be stable for connector upserts and evidence-room links.
    """
    return stable_id_slug(f"{project}:{signal}:{dedupe_key or asset_id}", fallback="gcp")
