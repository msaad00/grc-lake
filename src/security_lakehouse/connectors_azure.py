"""Azure cloud-posture evidence collector.

The fourth connector with a real runner. It collects read-only Azure
subscription posture signals — RBAC role assignments, policy assignments, and
resource posture — and emits them in the lake's raw evidence shape so they flow
through the same validate -> write -> pipeline path the ``github-security``,
``okta-identity`` and ``aws-posture`` runners use.

Two clients sit behind one interface, mirroring ``connectors_aws``:

* :class:`AzureClient` — authenticated read-only reads via the Azure SDK
  (``azure-identity`` + ``azure-mgmt-*``). The SDK imports are lazy (inside the
  client) so the base/test install never needs them; CI runs entirely off
  fixtures.
* :class:`AzureCliClient` — authenticated read-only reads via the ``az`` CLI.
  This keeps Azure Cloud Shell usable when the management SDK namespace shifts
  across installed versions.
* :class:`AzureFixtureClient` — reads ``role_assignments.json`` /
  ``policy_assignments.json`` / ``resources.json`` from a fixture directory so
  collection is fully testable without live Azure credentials.

The collector is strictly read-only and least-privilege: it only ever issues
list/read operations (``roleAssignments/read``, ``policyStates/read``,
``subscriptions/read`` and resource list reads) and never mutates Azure state.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.connector_errors import (
    ConnectorAccessError,
    ConnectorConfigError,
    ConnectorOperatorError,
)
from security_lakehouse.connector_ids import stable_id_slug
from security_lakehouse.delegation import azure_credential
from security_lakehouse.execution_mode import in_server_mode
from security_lakehouse.identity import classify_identity_type
from security_lakehouse.io import read_json
from security_lakehouse.models import utc_iso

# Identity/config controls that exist in controls/catalog.json. Verified before
# wiring (SOC2-CC6.1 logical access, ISO27001-A.5.15 access control,
# HIPAA-164.308(a)(4) access management).
IDENTITY_CONTROLS = ["SOC2-CC6.1", "ISO27001-A.5.15", "HIPAA-164.308(a)(4)"]
POLICY_CONTROLS = ["SOC2-CC6.1", "ISO27001-A.5.15"]
RESOURCE_CONTROLS = ["SOC2-CC6.1", "ISO27001-A.5.15"]

# Azure built-in roles that confer broad control-plane authority. A principal
# holding one of these at subscription scope is the noteworthy assignment for an
# auditor to review, so we surface it as an open finding.
PRIVILEGED_ROLE_NAMES = {"owner", "contributor", "user access administrator"}

_SAFE_ERROR_CODE = re.compile(r"^[A-Za-z][A-Za-z0-9.]{0,63}$")
_CREDENTIALS_UNAVAILABLE = (
    "Azure credentials are unavailable: DefaultAzureCredential found no usable identity "
    "(run az login, or configure a managed identity or service-principal environment variables)"
)


def _azure_access_error(exc: Exception, subscription_id: str) -> ConnectorOperatorError | None:
    """Map an Azure SDK or CLI failure to an operator-safe error, or ``None``.

    Duck-typed on ``azure.core.exceptions.HttpResponseError`` (``status_code``
    and ``error.code``) so the base install needs no Azure packages. Provider
    text is never copied; only a validated error code is.
    """
    if isinstance(exc, ConnectorOperatorError):
        return exc
    if type(exc).__name__ in {"CredentialUnavailableError", "ClientAuthenticationError"}:
        return ConnectorAccessError(_CREDENTIALS_UNAVAILABLE)
    status = getattr(exc, "status_code", None)
    raw_code = str(getattr(getattr(exc, "error", None), "code", "") or "")
    code = raw_code if _SAFE_ERROR_CODE.match(raw_code) else ""
    if status == 403 or code == "AuthorizationFailed":
        return ConnectorAccessError(
            f"Azure identity cannot read subscription {subscription_id} ({code or 'AuthorizationFailed'}); "
            "assign the Reader role at subscription scope"
        )
    if status == 404 or code in {"SubscriptionNotFound", "InvalidSubscriptionId"}:
        return ConnectorAccessError(
            f"Azure subscription {subscription_id} is not visible to this identity ({code or 'not found'})"
        )
    return None


def probe_azure_access(*, credentials: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    """Prove live, read-only access to the configured subscription.

    Reads the subscription itself (``Microsoft.Resources/subscriptions/read``)
    through the SDK, or the ``az`` CLI when the SDK is not installed, the same
    fallback sync uses. In hosted server mode the probe authenticates as the
    tenant's app registration (see :func:`security_lakehouse.delegation.azure_credential`)
    and never falls back to the CLI.
    """
    del options
    subscription_id = str(credentials.get("subscription_id") or "").strip()
    if not subscription_id:
        raise ConnectorConfigError("Azure probe requires subscription_id")
    try:
        client = build_azure_client(subscription_id, credentials, dict(os.environ))
        subscription = client.subscription()
    except Exception as exc:
        mapped = _azure_access_error(exc, subscription_id)
        if mapped is None:
            raise
        raise mapped from None
    return {
        "ok": True,
        "subscription_id": subscription_id,
        "subscription_state": str(subscription.get("state") or "unknown"),
        "capabilities": ["Microsoft.Resources/subscriptions/read"],
    }


def build_azure_client(
    subscription_id: str, credentials: dict[str, Any], env: dict[str, str]
) -> AzureClient | AzureCliClient:
    """The live client for ``subscription_id``: the tenant's app, or locally the ambient identity.

    A delegated credential always uses the SDK. Without one (local mode only;
    server mode raises), the SDK's ``DefaultAzureCredential`` is tried first and
    the ``az`` CLI login is the fallback.
    """
    delegated = azure_credential(credentials, env, label="azure-posture")
    if delegated is not None:
        return AzureClient(subscription_id, credential=delegated)
    try:
        return AzureClient(subscription_id)
    except (ConnectorConfigError, RuntimeError):
        return AzureCliClient(subscription_id)


class AzureClient:
    """Authenticated, read-only Azure subscription client backed by the SDK.

    The ``azure-identity`` / ``azure-mgmt-*`` imports are lazy so installs that
    never touch live Azure do not need them. ``credential`` is the tenant's
    delegated credential; without one, credentials resolve through
    ``DefaultAzureCredential`` (service-principal env vars, managed identity,
    Azure CLI login, etc.), which hosted server mode refuses.
    """

    def __init__(self, subscription_id: str, *, credential: Any = None) -> None:
        try:
            from azure.identity import DefaultAzureCredential  # type: ignore[import-not-found]  # noqa: PLC0415
            from azure.mgmt.authorization import (
                AuthorizationManagementClient,  # type: ignore[import-not-found]  # noqa: PLC0415
            )

            try:
                from azure.mgmt.resource.resources import ResourceManagementClient  # noqa: PLC0415
            except ImportError:
                from azure.mgmt.resource import (
                    ResourceManagementClient,  # type: ignore[import-not-found]  # noqa: PLC0415
                )
            try:
                from azure.mgmt.resource.policy import PolicyClient  # noqa: PLC0415
            except ImportError:
                from azure.mgmt.resource import PolicyClient  # type: ignore[attr-defined]  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover - exercised only with live Azure
            raise ConnectorConfigError(
                "azure-posture live collection requires azure-identity and azure-mgmt-* "
                "packages with resource and policy clients; install the cloud extra or use --fixture-dir"
            ) from exc
        self.subscription_id = subscription_id
        if credential is None:
            if in_server_mode():
                raise ConnectorConfigError(
                    "azure-posture in hosted mode requires the tenant's app registration credentials; "
                    "the server never collects with its own Azure identity"
                )
            credential = DefaultAzureCredential()
        self._credential = credential
        self._authz = AuthorizationManagementClient(credential, subscription_id)
        self._policy = PolicyClient(credential, subscription_id)
        self._resources = ResourceManagementClient(credential, subscription_id)

    def subscription(self) -> dict[str, Any]:
        from azure.mgmt.resource.subscriptions import (
            SubscriptionClient,  # type: ignore[import-not-found]  # noqa: PLC0415
        )

        return self._as_dict(SubscriptionClient(self._credential).subscriptions.get(self.subscription_id))

    def role_assignments(self) -> list[dict[str, Any]]:
        return [self._as_dict(item) for item in self._authz.role_assignments.list_for_subscription()]

    def role_definitions(self) -> list[dict[str, Any]]:
        scope = f"/subscriptions/{self.subscription_id}"
        return [self._as_dict(item) for item in self._authz.role_definitions.list(scope)]

    def policy_assignments(self) -> list[dict[str, Any]]:
        if self._policy is None:
            raise ConnectorAccessError("Azure policy collection unavailable; assessment was not completed")
        return [self._as_dict(item) for item in self._policy.policy_assignments.list()]

    def resources(self) -> list[dict[str, Any]]:
        return [self._as_dict(item) for item in self._resources.resources.list()]

    @staticmethod
    def _as_dict(item: Any) -> dict[str, Any]:
        if isinstance(item, dict):
            return item
        as_dict = getattr(item, "as_dict", None)
        if callable(as_dict):
            payload = as_dict()
            if isinstance(payload, dict):
                return payload
        return {}


class AzureCliClient:
    """Authenticated, read-only Azure subscription client backed by ``az``.

    Azure Cloud Shell already has a logged-in ``az`` session. Using subprocess
    argument arrays avoids shell expansion, and all commands are read-only list
    calls scoped to the configured subscription.
    """

    def __init__(self, subscription_id: str, *, executable: str = "az") -> None:
        if in_server_mode():
            raise ConnectorConfigError("the az CLI login is the server's own identity and is not used in hosted mode")
        self.subscription_id = subscription_id
        resolved = shutil.which(executable)
        if resolved is None:
            raise ConnectorConfigError(
                "azure-posture live access requires the Azure SDK (cloud extra) or the az CLI on PATH"
            )
        self._az = resolved

    def subscription(self) -> dict[str, Any]:
        rows = self._run_json(["account", "show"])
        return rows[0] if rows else {}

    def role_assignments(self) -> list[dict[str, Any]]:
        return self._run_json(["role", "assignment", "list", "--include-inherited"])

    def role_definitions(self) -> list[dict[str, Any]]:
        return self._run_json(["role", "definition", "list"])

    def policy_assignments(self) -> list[dict[str, Any]]:
        return self._run_json(["policy", "assignment", "list"])

    def resources(self) -> list[dict[str, Any]]:
        return self._run_json(["resource", "list"])

    def _run_json(self, args: list[str]) -> list[dict[str, Any]]:
        cmd = [self._az, *args, "--subscription", self.subscription_id, "--output", "json"]
        try:
            completed = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=90,
            )
        except subprocess.TimeoutExpired as exc:
            raise ConnectorAccessError("azure CLI command timed out during azure-posture collection") from exc
        except subprocess.CalledProcessError as exc:
            detail = _scrub_cli_error(exc.stderr)
            if "az login" in detail:
                raise ConnectorAccessError(
                    "azure CLI is not logged in; run az login for the subscription before syncing"
                ) from exc
            if "AuthorizationFailed" in detail:
                raise ConnectorAccessError(
                    f"Azure identity cannot read subscription {self.subscription_id} (AuthorizationFailed); "
                    "assign the Reader role at subscription scope"
                ) from exc
            raise RuntimeError(f"azure CLI command failed during azure-posture collection: {detail}") from exc

        try:
            payload = json.loads(completed.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise ConnectorAccessError("azure CLI returned invalid JSON during azure-posture collection") from exc
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            value = payload.get("value")
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            return [payload]
        return []


class AzureFixtureClient:
    """Offline Azure client backed by a fixture directory."""

    def __init__(
        self, fixture_dir: str | Path, *, subscription_id: str = "00000000-0000-0000-0000-000000000000"
    ) -> None:
        self.fixture = Path(fixture_dir)
        self.subscription_id = subscription_id

    def role_assignments(self) -> list[dict[str, Any]]:
        return self._read_list("role_assignments.json")

    def role_definitions(self) -> list[dict[str, Any]]:
        return self._read_list("role_definitions.json")

    def policy_assignments(self) -> list[dict[str, Any]]:
        return self._read_list("policy_assignments.json")

    def resources(self) -> list[dict[str, Any]]:
        return self._read_list("resources.json")

    def _read(self, name: str) -> Any:
        path = self.fixture / name
        return read_json(path) if path.exists() else []

    def _read_list(self, name: str) -> list[dict[str, Any]]:
        payload = self._read(name)
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        return []


def collect_azure_evidence(
    client: AzureClient | AzureCliClient | AzureFixtureClient,
    *,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    """Collect normalized raw posture evidence from an Azure subscription.

    Emits, per collection:

    * one role-assignment event per RBAC assignment (-> identity controls; an
      Owner / Contributor / User Access Administrator assignment at subscription
      scope is a high open finding for review),
    * one policy-assignment event per Azure Policy assignment (-> policy
      controls; a disabled enforcement mode is an open finding),
    * one resource event per subscription resource (-> resource controls).

    Every event passes :func:`security_lakehouse.validation.validate_raw_events`.
    """
    now = collected_at or datetime.now(UTC)
    subscription = _subscription_slug(client.subscription_id)
    rows: list[dict[str, Any]] = []

    role_name_by_id = _role_definition_name_map(client)
    for assignment in client.role_assignments():
        event = _role_assignment_event(subscription, assignment, now, tenant_id, role_name_by_id)
        if event is not None:
            rows.append(event)

    for assignment in client.policy_assignments():
        event = _policy_assignment_event(subscription, assignment, now, tenant_id)
        if event is not None:
            rows.append(event)

    for resource in client.resources():
        event = _resource_event(subscription, resource, now, tenant_id)
        if event is not None:
            rows.append(event)

    return rows


def _role_assignment_event(
    subscription: str,
    assignment: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
    role_name_by_id: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    props = _props(assignment)
    assignment_id = str(assignment.get("id") or assignment.get("name") or props.get("scope") or "").strip()
    if not assignment_id:
        return None
    role_definition_id = str(props.get("role_definition_id") or props.get("roleDefinitionId") or "").strip()
    role_name = str(props.get("role_definition_name") or props.get("roleDefinitionName") or "").strip()
    if not role_name and role_definition_id:
        # The SDK role_assignments payload carries only the role definition id
        # (a GUID path), never the display name; resolve it from the role
        # definition catalog so privileged-role detection has a name to match.
        role_name = _resolve_role_name(role_definition_id, role_name_by_id or {})
    principal_id = str(props.get("principal_id") or props.get("principalId") or "").strip()
    principal_type = str(props.get("principal_type") or props.get("principalType") or "Unknown").strip()
    scope = str(props.get("scope") or f"/subscriptions/{subscription}").strip()
    privileged = role_name.lower() in PRIVILEGED_ROLE_NAMES
    subscription_scope = scope.lower().rstrip("/").endswith(f"/subscriptions/{subscription}".lower())
    noteworthy = privileged and subscription_scope
    return _event(
        subscription=subscription,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="role_assignment",
        dedupe_key=assignment_id,
        event_type="azure.cloud.role_assignment",
        asset_id=f"azure:role-assignment:{_id_slug(assignment_id)}",
        asset_type="identity_role_assignment",
        controls=IDENTITY_CONTROLS,
        status="open" if noteworthy else "observed",
        severity="high" if noteworthy else "info",
        evidence_ref=assignment_id,
        attributes={
            "assignment_id": assignment_id,
            "role_name": role_name,
            "role_definition_id": role_definition_id,
            "principal_id": principal_id,
            "principal_type": principal_type,
            "identity_type": classify_identity_type(principal_type=principal_type),
            "scope": scope,
            "privileged_role": privileged,
            "subscription_scope": subscription_scope,
        },
    )


def _policy_assignment_event(
    subscription: str,
    assignment: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any] | None:
    props = _props(assignment)
    assignment_id = str(assignment.get("id") or assignment.get("name") or "").strip()
    if not assignment_id:
        return None
    display_name = str(props.get("display_name") or props.get("displayName") or assignment.get("name") or "").strip()
    enforcement = str(props.get("enforcement_mode") or props.get("enforcementMode") or "Default").strip()
    scope = str(props.get("scope") or f"/subscriptions/{subscription}").strip()
    enforced = enforcement.lower() == "default"
    return _event(
        subscription=subscription,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="policy_assignment",
        dedupe_key=assignment_id,
        event_type="azure.cloud.policy_assignment",
        asset_id=f"azure:policy-assignment:{_id_slug(assignment_id)}",
        asset_type="cloud_policy",
        controls=POLICY_CONTROLS,
        # A policy assignment that is not enforcing is the noteworthy one.
        status="observed" if enforced else "open",
        severity="info" if enforced else "medium",
        evidence_ref=assignment_id,
        attributes={
            "assignment_id": assignment_id,
            "display_name": display_name,
            "enforcement_mode": enforcement,
            "is_enforced": enforced,
            "scope": scope,
            "policy_definition_id": props.get("policy_definition_id") or props.get("policyDefinitionId"),
        },
    )


def _resource_event(
    subscription: str,
    resource: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any] | None:
    resource_id = str(resource.get("id") or "").strip()
    if not resource_id:
        return None
    name = str(resource.get("name") or "").strip()
    resource_type = str(resource.get("type") or "").strip()
    location = str(resource.get("location") or "").strip()
    return _event(
        subscription=subscription,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="resource",
        dedupe_key=resource_id,
        event_type="azure.cloud.resource",
        asset_id=f"azure:resource:{_id_slug(resource_id)}",
        asset_type="cloud_resource",
        controls=RESOURCE_CONTROLS,
        status="observed",
        severity="info",
        evidence_ref=resource_id,
        attributes={
            "resource_id": resource_id,
            "resource_name": name,
            "resource_type": resource_type,
            "location": location,
            "subscription_id": subscription,
        },
    )


def _role_definition_name_map(
    client: AzureClient | AzureCliClient | AzureFixtureClient,
) -> dict[str, str]:
    """Map Azure role definition ids -> display names, keyed for tolerant lookup.

    Resolution is best-effort: a least-privilege reader may lack
    ``roleDefinitions/read``, and not every client version exposes the SDK
    surface, so any failure yields an empty map and role names stay blank rather
    than failing the whole collection. Each definition is indexed by its full
    resource id, by its GUID name, and by the GUID tail of its id so an
    assignment's ``role_definition_id`` matches regardless of which form it
    carries.
    """
    getter = getattr(client, "role_definitions", None)
    if not callable(getter):
        return {}
    try:
        definitions = getter()
    except Exception:  # noqa: BLE001 - best-effort enrichment, never fatal
        return {}
    mapping: dict[str, str] = {}
    for definition in definitions or []:
        if not isinstance(definition, dict):
            continue
        props = _props(definition)
        name = str(props.get("role_name") or props.get("roleName") or "").strip()
        if not name:
            continue
        full_id = str(definition.get("id") or "").strip().lower()
        guid = str(definition.get("name") or "").strip().lower()
        if full_id:
            mapping[full_id] = name
            mapping[full_id.rsplit("/", 1)[-1]] = name
        if guid:
            mapping[guid] = name
    return mapping


def _resolve_role_name(role_definition_id: str, role_name_by_id: dict[str, str]) -> str:
    key = role_definition_id.lower()
    return role_name_by_id.get(key) or role_name_by_id.get(key.rsplit("/", 1)[-1], "")


def _props(item: dict[str, Any]) -> dict[str, Any]:
    """Return the SDK ``properties`` sub-object, accepting flat fixtures too.

    Azure SDK ``as_dict`` payloads nest most fields under ``properties``; small
    fixtures may inline them at the top level, so we merge both views with the
    nested properties taking precedence.
    """
    merged: dict[str, Any] = {k: v for k, v in item.items() if k != "properties"}
    nested = item.get("properties")
    if isinstance(nested, dict):
        merged.update(nested)
    return merged


def _event(
    *,
    subscription: str,
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
    stable = _stable_suffix(subscription=subscription, signal=signal, asset_id=asset_id, dedupe_key=dedupe_key)
    return {
        "event_id": f"azure-{stable}",
        "tenant_id": tenant_id,
        "workspace_id": "default",
        "event_time": utc_iso(collected_at),
        "source": "azure",
        "event_type": event_type,
        "entity": {
            "asset_id": asset_id,
            "asset_type": asset_type,
            "asset_owner": subscription,
            "environment": "prod",
            "org": subscription,
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


def _subscription_slug(subscription_id: str) -> str:
    slug = re.sub(r"[^a-z0-9_.:-]+", "-", str(subscription_id).lower()).strip("-")
    return slug or "azure-subscription"


def _id_slug(value: str) -> str:
    return stable_id_slug(str(value), fallback="azure", keep="tail")


def _stable_suffix(*, subscription: str, signal: str, asset_id: str, dedupe_key: str | None) -> str:
    """Build a deterministic connector-local id without hashing identity data.

    The pipeline computes the canonical raw evidence hash after collection. These
    IDs only need to be stable for connector upserts and evidence-room links.
    Azure resource IDs share long common prefixes (the subscription and provider
    path) and carry their distinguishing name in the tail, so the slug keeps the
    tail when it exceeds the length cap, plus a digest so two resources that
    share a tail (same name, different resource group) stay distinct.
    """
    return stable_id_slug(f"{subscription}:{signal}:{dedupe_key or asset_id}", fallback="azure", keep="tail")


def _scrub_cli_error(stderr: str | None) -> str:
    message = " ".join(str(stderr or "").split())
    if not message:
        return "no stderr"
    return message[:300]
