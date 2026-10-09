"""AWS posture-evidence collector.

The third connector with a real runner. It collects read-only IAM posture
signals — IAM users and their MFA-device enrollment, plus the account password
policy — and emits them in the lake's raw evidence shape so they flow through
the same validate -> write -> pipeline path the ``github-security`` and
``okta-identity`` runners use.

Two clients sit behind one interface, mirroring ``connectors_okta``:

* :class:`AWSClient` — authenticated read-only IAM reads via ``boto3``. The
  ``boto3`` import is lazy (inside the client) so the base/test install never
  needs it; CI runs entirely off fixtures.
* :class:`AWSFixtureClient` — reads ``iam_users.json`` / ``mfa_devices.json``
  / ``password_policy.json`` from a fixture directory so collection is fully
  testable without live AWS credentials.

The collector is strictly read-only and least-privilege: it only ever issues
``ListUsers`` / ``ListMFADevices`` / ``GetAccountPasswordPolicy`` /
``GetAccountSummary`` calls and never mutates AWS state.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.connector_errors import (
    CollectionGapError,
    ConnectorAccessError,
    ConnectorConfigError,
)
from security_lakehouse.connector_ids import stable_id_slug
from security_lakehouse.delegation import require_aws_delegation
from security_lakehouse.identity import classify_identity_type
from security_lakehouse.io import read_json
from security_lakehouse.models import utc_iso

CONNECTOR_ID = "aws-posture"

# Identity/config controls that exist in controls/catalog.json. Verified before
# wiring (SOC2-CC6.1 logical access, ISO27001-A.5.15 access control,
# HIPAA-164.308(a)(4) access management).
IDENTITY_CONTROLS = ["SOC2-CC6.1", "ISO27001-A.5.15", "HIPAA-164.308(a)(4)"]
# Each finding also carries the CIS AWS Foundations Benchmark control it tests, so
# CIS coverage is evaluated from the same signal as the SOC 2 / ISO / HIPAA mapping.
MFA_CONTROLS = ["SOC2-CC6.1", "HIPAA-164.308(a)(4)", "CIS-AWS-1.10"]
POLICY_CONTROLS = ["SOC2-CC6.1", "ISO27001-A.5.15", "CIS-AWS-1.8"]
ACCESS_KEY_CONTROLS = [*IDENTITY_CONTROLS, "CIS-AWS-1.14"]

# AWS-recommended password-policy floor used to score the account policy. A
# policy that meets every one of these is "strong"; anything weaker is an open
# config finding an auditor should look at.
MIN_PASSWORD_LENGTH = 14

# Access-key rotation SLO. For a service identity (no console / no MFA) the
# relevant control is key hygiene, not MFA: an active access key older than this,
# or more than one active key, is the finding an auditor should review.
MAX_ACCESS_KEY_AGE_DAYS = 90

# The read action each optional inventory service needs, matching
# deploy/aws/grc-lake-posture-readonly-role.yaml, so a denied read names the
# permission to grant.
INVENTORY_PERMISSIONS = {
    "ec2": "ec2:DescribeInstances",
    "s3": "s3:ListAllMyBuckets",
    "rds": "rds:DescribeDBInstances",
    "cloudtrail": "cloudtrail:DescribeTrails",
    "config": "config:DescribeConfigurationRecorders",
    "securityhub": "securityhub:DescribeHub",
    "organizations": "organizations:DescribeOrganization",
}
_SAFE_ERROR_CODE = re.compile(r"^[A-Za-z][A-Za-z0-9.]{0,63}$")


def _aws_error_code(exc: Exception) -> str:
    """Best-effort botocore ``ClientError`` code without importing botocore.

    Lets the client distinguish an *expected* ``NoSuchEntity`` (a real "not
    configured" answer) from any other error (an auth failure, or a throttle
    that survived boto3's built-in retries) that must not be swallowed into a
    false-pass posture result.
    """
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict):
            return str(error.get("Code") or "")
    return ""


class AWSClient:
    """Authenticated, read-only AWS IAM client backed by ``boto3``.

    ``boto3`` is imported lazily so installs that never touch live AWS do not
    need it. Two auth modes:

    * **Ambient** (default) — credentials resolve through boto3's standard
      provider chain (``AWS_*`` env vars / profiles / IRSA / instance roles).
      Use this when GRC Lake already runs as the reader identity.
    * **Assume-role** — when ``role_arn`` is given, GRC Lake calls
      ``sts:AssumeRole`` (with the customer's ``external_id`` for confused-deputy
      protection) and reads with the returned short-lived session. This is the
      hosted-GRC connect model: the customer deploys the read-only role
      (``deploy/aws/grc-lake-posture-readonly-role.yaml``) and hands GRC Lake
      only the Role ARN + External ID — never a key. The base session used to
      assume is itself ambient (the runtime's pod/instance identity).
    """

    def __init__(
        self,
        *,
        region_name: str | None = None,
        role_arn: str | None = None,
        external_id: str | None = None,
        session_name: str = "trustops-posture",
    ) -> None:
        require_aws_delegation(role_arn, external_id, label="aws-posture")
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover - exercised only with live AWS
            raise ConnectorConfigError(
                "aws-posture live collection requires boto3; install the cloud extra or use --fixture-dir"
            ) from exc
        if role_arn:
            sts = boto3.client("sts", region_name=region_name)
            assume_kwargs: dict[str, Any] = {"RoleArn": role_arn, "RoleSessionName": session_name}
            if external_id:
                assume_kwargs["ExternalId"] = external_id
            creds = sts.assume_role(**assume_kwargs)["Credentials"]
            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region_name,
            )
            self._session = session
            self._iam = session.client("iam")
        else:
            self._session = None
            self._boto3 = boto3
            self._iam = boto3.client("iam", region_name=region_name)

    def service_client(self, service: str, *, region_name: str | None = None) -> Any:
        """Create a provider client from the same short-lived assumed session."""
        if self._session is not None:
            return self._session.client(service, region_name=region_name)
        return self._boto3.client(service, region_name=region_name)

    def caller_identity(self) -> dict[str, Any]:
        """``sts:GetCallerIdentity`` for the identity this client reads as."""
        return dict(self.service_client("sts").get_caller_identity())

    def users(self) -> list[dict[str, Any]]:
        users: list[dict[str, Any]] = []
        paginator = self._iam.get_paginator("list_users")
        for page in paginator.paginate():
            users.extend(page.get("Users", []))
        return users

    def mfa_devices(self, user_name: str) -> list[dict[str, Any]]:
        devices: list[dict[str, Any]] = []
        paginator = self._iam.get_paginator("list_mfa_devices")
        for page in paginator.paginate(UserName=user_name):
            devices.extend(page.get("MFADevices", []))
        return devices

    def password_policy(self) -> dict[str, Any]:
        try:
            return self._iam.get_account_password_policy().get("PasswordPolicy", {})
        except Exception as exc:  # narrowed below
            # NoSuchEntity means no policy is set (a real "empty" answer). Any
            # other error must surface rather than read as "no policy", which
            # would be a false pass on the password-policy control.
            if _aws_error_code(exc) == "NoSuchEntity":
                return {}
            raise

    def account_summary(self) -> dict[str, Any]:
        try:
            return self._iam.get_account_summary().get("SummaryMap", {})
        except Exception:  # noqa: BLE001 - summary is optional context
            return {}

    def console_access(self, user_name: str) -> bool:
        """True when the IAM user has a console login profile (a password).

        MFA only applies to console (human) sign-in. A user with no login
        profile is a programmatic/service identity that authenticates with
        access keys, so a missing MFA device is not a finding for it. ``NoSuchEntity``
        from ``GetLoginProfile`` means no console password.
        """
        try:
            self._iam.get_login_profile(UserName=user_name)
            return True
        except Exception as exc:  # narrowed below
            # NoSuchEntity => no console password => programmatic-only identity.
            # Any other error must surface: silently returning False would drop a
            # human account's missing-MFA finding.
            if _aws_error_code(exc) == "NoSuchEntity":
                return False
            raise

    def access_keys(self, user_name: str) -> list[dict[str, Any]]:
        """Access-key metadata (id, status, create date) for an IAM user."""
        keys: list[dict[str, Any]] = []
        paginator = self._iam.get_paginator("list_access_keys")
        for page in paginator.paginate(UserName=user_name):
            keys.extend(page.get("AccessKeyMetadata", []))
        return keys

    def inventory(self, service: str, *, region_name: str) -> list[dict[str, Any]]:
        """Read a bounded normalized inventory slice for one AWS service."""
        client = self.service_client(service, region_name=region_name)
        if service == "ec2":
            rows: list[dict[str, Any]] = []
            for page in client.get_paginator("describe_instances").paginate():
                for reservation in page.get("Reservations", []):
                    for item in reservation.get("Instances", []):
                        instance_id = str(item.get("InstanceId") or "")
                        if instance_id:
                            rows.append({"id": instance_id, "state": (item.get("State") or {}).get("Name")})
            return rows
        if service == "s3":
            return [{"id": str(row.get("Name"))} for row in client.list_buckets().get("Buckets", []) if row.get("Name")]
        if service == "rds":
            return [
                {
                    "id": str(row.get("DBInstanceIdentifier")),
                    "arn": row.get("DBInstanceArn"),
                    "state": row.get("DBInstanceStatus"),
                }
                for page in client.get_paginator("describe_db_instances").paginate()
                for row in page.get("DBInstances", [])
                if row.get("DBInstanceIdentifier")
            ]
        if service == "cloudtrail":
            return [
                {"id": str(row.get("Name")), "arn": row.get("TrailARN"), "multi_region": row.get("IsMultiRegionTrail")}
                for row in client.describe_trails(includeShadowTrails=False).get("trailList", [])
                if row.get("Name")
            ]
        if service == "config":
            return [
                {
                    "id": str(row.get("name")),
                    "role_arn": row.get("roleARN"),
                    "recording_group": row.get("recordingGroup"),
                }
                for row in client.describe_configuration_recorders().get("ConfigurationRecorders", [])
                if row.get("name")
            ]
        if service == "securityhub":
            hub = client.describe_hub()
            return [{"id": "hub", "arn": hub.get("HubArn"), "auto_enable": hub.get("AutoEnable")}]
        if service == "organizations":
            organization = client.describe_organization().get("Organization", {})
            organization_id = str(organization.get("Id") or "organization")
            return [
                {"id": organization_id, "arn": organization.get("Arn"), "feature_set": organization.get("FeatureSet")}
            ]
        raise ValueError(f"unsupported AWS inventory service: {service}")


class AWSFixtureClient:
    """Offline AWS IAM client backed by a fixture directory."""

    def __init__(self, fixture_dir: str | Path) -> None:
        self.fixture = Path(fixture_dir)

    def users(self) -> list[dict[str, Any]]:
        return self._read_list("iam_users.json")

    def mfa_devices(self, user_name: str) -> list[dict[str, Any]]:
        payload = self._read("mfa_devices.json")
        if isinstance(payload, dict):
            items = payload.get(str(user_name), [])
            return [item for item in items if isinstance(item, dict)]
        # A flat list fixture: keep only devices that name this user.
        return [item for item in payload if isinstance(item, dict) and str(item.get("UserName")) == str(user_name)]

    def password_policy(self) -> dict[str, Any]:
        payload = self._read("password_policy.json")
        if isinstance(payload, dict):
            # Accept either a bare policy or an envelope under PasswordPolicy.
            return payload.get("PasswordPolicy", payload)
        return {}

    def account_summary(self) -> dict[str, Any]:
        payload = self._read("account_summary.json")
        if isinstance(payload, dict):
            return payload.get("SummaryMap", payload)
        return {}

    def console_access(self, user_name: str) -> bool:
        """Console (login-profile) users come from ``login_profiles.json``.

        The file is a JSON list of usernames that have a console password. When
        it is absent the data is unknown, so we conservatively treat the user as
        a console user (surface a missing-MFA finding rather than hide it).
        """
        path = self.fixture / "login_profiles.json"
        if not path.exists():
            return True
        payload = read_json(path)
        names = payload if isinstance(payload, list) else []
        return str(user_name) in {str(name) for name in names}

    def access_keys(self, user_name: str) -> list[dict[str, Any]]:
        payload = self._read("access_keys.json")
        if isinstance(payload, dict):
            items = payload.get(str(user_name), [])
            return [item for item in items if isinstance(item, dict)]
        return [item for item in payload if isinstance(item, dict) and str(item.get("UserName")) == str(user_name)]

    def _read(self, name: str) -> Any:
        path = self.fixture / name
        return read_json(path) if path.exists() else []

    def _read_list(self, name: str) -> list[dict[str, Any]]:
        payload = self._read(name)
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        return []


def probe_aws_access(
    *,
    credentials: dict[str, Any],
    options: dict[str, Any],
    allow_ambient_credentials: bool = False,
) -> dict[str, Any]:
    """Prove live AWS access for the configured account, fail-closed.

    Two credential modes, matching sync:

    * ``role_arn`` (+ ``external_id``): ``sts:AssumeRole`` into the customer's
      read-only role. This is the production path and the only one accepted
      unless the caller opts in to ambient credentials.
    * local credential chain (``AWS_PROFILE`` / SSO / env), only when
      ``allow_ambient_credentials`` is set. The CLI sets it; the API does not,
      so a server never probes with its own runtime identity by default.

    Either way ``sts:GetCallerIdentity`` must resolve to the configured
    ``account_id`` and ``iam:ListUsers`` must succeed.
    """
    account_id = str(credentials.get("account_id") or "").strip()
    role_arn = str(credentials.get("role_arn") or "").strip()
    external_id = str(credentials.get("external_id") or "").strip()
    region = str(options.get("region") or credentials.get("region") or "").strip() or None
    if not account_id:
        raise ConnectorConfigError("AWS probe requires account_id")
    if not role_arn and not allow_ambient_credentials:
        raise ConnectorConfigError(
            "AWS probe requires role_arn (and external_id) to assume the read-only role; "
            "the local AWS credential chain can only be probed from the CLI"
        )
    client = AWSClient(
        region_name=region,
        role_arn=role_arn or None,
        external_id=external_id or None,
    )
    verify_aws_account(client, account_id)
    users = client.users()
    result: dict[str, Any] = {
        "ok": True,
        "account_id": account_id,
        "credential_mode": "assume_role" if role_arn else "local_credential_chain",
        "capabilities": [
            *(["sts:AssumeRole"] if role_arn else []),
            "sts:GetCallerIdentity",
            "iam:ListUsers",
        ],
        "principal_count": len(users),
    }
    if role_arn:
        result["role_arn"] = role_arn
    return result


def verify_aws_account(client: Any, account_id: str) -> None:
    """Fail when the resolved AWS identity belongs to a different account."""
    actual = str(client.caller_identity().get("Account") or "").strip()
    if actual != account_id:
        raise ConnectorAccessError(
            f"AWS credentials resolve to account {actual or 'unknown'}, "
            f"but the connector is configured for account {account_id}"
        )


def collect_aws_evidence(
    client: AWSClient | AWSFixtureClient,
    *,
    account_id: str,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    """Collect normalized raw posture evidence from an AWS account.

    Emits, per collection:

    * one identity-access event per IAM user (-> identity controls),
    * one MFA-enrollment event per IAM user (device count -> MFA controls,
      a user with no MFA device is a high-severity open finding),
    * one account password-policy config event (strength -> policy controls).

    Every event passes :func:`security_lakehouse.validation.validate_raw_events`.
    """
    now = collected_at or datetime.now(UTC)
    account = _account_slug(account_id)
    rows: list[dict[str, Any]] = []

    for user in client.users():
        user_name = str(user.get("UserName") or "").strip()
        if not user_name:
            continue
        rows.append(_user_event(account, user, now, tenant_id))
        devices = client.mfa_devices(user_name)
        console = client.console_access(user_name)
        rows.append(_mfa_event(account, user_name, user, devices, now, tenant_id, console_access=console))
        keys = client.access_keys(user_name)
        if keys:
            rows.append(_access_key_event(account, user_name, user, keys, now, tenant_id, console_access=console))

    rows.append(_policy_event(account, client.password_policy(), now, tenant_id))
    return rows


def collect_aws_inventory_evidence(
    client: Any,
    *,
    account_id: str,
    regions: list[str],
    services: list[str],
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    """Collect selected inventory while isolating unsupported/denied service reads."""
    now = collected_at or datetime.now(UTC)
    account = _account_slug(account_id)
    rows: list[dict[str, Any]] = []
    global_services = {"s3", "organizations"}
    seen_global: set[str] = set()
    gaps: dict[str, CollectionGapError] = {}
    for region in regions:
        for service in services:
            if service in global_services and service in seen_global:
                continue
            collection = f"inventory:{service}" if service in global_services else f"inventory:{service}:{region}"
            try:
                resources = client.inventory(service, region_name=region)
            except Exception as exc:  # noqa: BLE001 - one denied service must not discard successful inventory
                gaps[collection] = _inventory_gap(exc, service=service, region=region, collection=collection)
                continue
            if service in global_services:
                seen_global.add(service)
                gaps.pop(collection, None)
            for resource in resources:
                resource_id = str(resource.get("id") or "").strip()
                if not resource_id:
                    continue
                evidence_ref = str(resource.get("arn") or f"aws:{service}:{region}:{account}:{resource_id}")
                rows.append(
                    _event(
                        account=account,
                        collected_at=now,
                        tenant_id=tenant_id,
                        signal=f"inventory-{service}",
                        event_type=f"aws.inventory.{service}",
                        asset_id=f"aws:{service}:{region}:{resource_id}",
                        asset_type=f"aws_{service}_resource",
                        controls=IDENTITY_CONTROLS,
                        status="open"
                        if service == "cloudtrail" and resource.get("multi_region") is False
                        else "observed",
                        severity="medium"
                        if service == "cloudtrail" and resource.get("multi_region") is False
                        else "info",
                        evidence_ref=evidence_ref,
                        attributes={**resource, "account_id": account, "region": region, "service": service},
                    )
                )
    rows.extend(_gap_event(account, gap, now, tenant_id) for gap in gaps.values())
    return rows


def _inventory_gap(exc: Exception, *, service: str, region: str, collection: str) -> CollectionGapError:
    code = _aws_error_code(exc)
    safe_code = code if _SAFE_ERROR_CODE.match(code) else ""
    denied = "AccessDenied" in safe_code or safe_code.startswith("Unauthorized")
    scope = (
        f"AWS {service} inventory" if collection == f"inventory:{service}" else f"AWS {service} inventory in {region}"
    )
    permission = INVENTORY_PERMISSIONS.get(service) if denied else None
    detail = safe_code or "read failed"
    if permission:
        detail = f"{detail}; grant {permission}"
    return CollectionGapError(
        f"{scope} was not collected ({detail})",
        collection=collection,
        reason="permission_denied" if denied else "read_failed",
        permission=permission,
    )


def _gap_event(account: str, gap: CollectionGapError, collected_at: datetime, tenant_id: str) -> dict[str, Any]:
    """A coverage-gap row: an actionable open item that neither passes nor fails a control."""
    return _event(
        account=account,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="collection_gap",
        dedupe_key=gap.collection,
        event_type="aws.collection_gap",
        asset_id=f"aws:account:{account}",
        asset_type="collection_scope",
        controls=[],
        status="open",
        severity="low",
        evidence_ref=f"aws:{account}:collection-gap:{gap.collection}",
        attributes=gap.attributes(),
    )


def _user_event(
    account: str,
    user: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any]:
    user_name = str(user["UserName"])
    arn = str(user.get("Arn") or f"arn:aws:iam::{account}:user/{user_name}")
    # A user attached to an admin/privileged path is worth surfacing for review.
    path = str(user.get("Path") or "/")
    privileged = "admin" in path.lower() or "admin" in user_name.lower()
    return _event(
        account=account,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="identity_access",
        dedupe_key=user_name,
        event_type="aws.iam.user_access",
        asset_id=f"aws:iam:user/{user_name}",
        asset_type="identity_account",
        controls=IDENTITY_CONTROLS,
        # Privileged-named principals are the noteworthy ones for review.
        status="open" if privileged else "observed",
        severity="high" if privileged else "info",
        evidence_ref=arn,
        attributes={
            "user_name": user_name,
            "arn": arn,
            "user_id": user.get("UserId"),
            "path": path,
            "create_date": _iso_or_none(user.get("CreateDate")),
            "password_last_used": _iso_or_none(user.get("PasswordLastUsed")),
            "privileged": privileged,
        },
    )


def _mfa_event(
    account: str,
    user_name: str,
    user: dict[str, Any],
    devices: list[dict[str, Any]],
    collected_at: datetime,
    tenant_id: str,
    *,
    console_access: bool = True,
) -> dict[str, Any]:
    device_serials = sorted(
        str(d.get("SerialNumber")) for d in devices if isinstance(d, dict) and d.get("SerialNumber")
    )
    enrolled = bool(device_serials)
    arn = str(user.get("Arn") or f"arn:aws:iam::{account}:user/{user_name}")
    # MFA is a console (human sign-in) control. A key-only programmatic/service
    # identity has no login profile, so a missing MFA device is not a finding for
    # it — only a console user without MFA is the finding worth raising.
    needs_mfa = console_access and not enrolled
    return _event(
        account=account,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="mfa_enrollment",
        dedupe_key=user_name,
        event_type="aws.iam.mfa_enrollment",
        asset_id=f"aws:iam:user/{user_name}",
        asset_type="identity_account",
        controls=MFA_CONTROLS,
        status="observed" if not console_access else ("open" if needs_mfa else "pass"),
        severity="high" if needs_mfa else "info",
        evidence_ref=f"{arn}/mfa-devices",
        attributes={
            "user_name": user_name,
            "console_access": console_access,
            "identity_type": classify_identity_type(console_access=console_access),
            "mfa_enrolled": enrolled,
            "mfa_device_count": len(device_serials),
            "mfa_device_serials": device_serials,
            "needs_mfa": needs_mfa,
            # Surface why a key-only identity is not flagged, so the posture is
            # self-explanatory to an auditor.
            "mfa_not_applicable": (not console_access),
        },
    )


def _access_key_age_days(create_date: Any, now: datetime) -> int | None:
    """Days since an access key was created, from a datetime or ISO-8601 string."""
    if isinstance(create_date, datetime):
        created = create_date
    else:
        text = str(create_date or "").strip()
        if not text:
            return None
        try:
            created = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    return (now - created).days


def _access_key_event(
    account: str,
    user_name: str,
    user: dict[str, Any],
    keys: list[dict[str, Any]],
    collected_at: datetime,
    tenant_id: str,
    *,
    console_access: bool = True,
) -> dict[str, Any]:
    arn = str(user.get("Arn") or f"arn:aws:iam::{account}:user/{user_name}")
    active = [k for k in keys if isinstance(k, dict) and str(k.get("Status")) == "Active"]
    active_ages = [_access_key_age_days(k.get("CreateDate"), collected_at) for k in active]
    ages = [age for age in active_ages if age is not None]
    # An active key whose CreateDate is missing or unparseable must not read as
    # freshly rotated (oldest=0). Treat unknown age as stale so a genuinely old
    # key can't score a false pass on the rotation control.
    unknown_age = any(age is None for age in active_ages)
    oldest = max(ages) if ages else 0
    stale = oldest > MAX_ACCESS_KEY_AGE_DAYS or unknown_age
    multiple_active = len(active) > 1
    # Key rotation is the access-management control that applies to a service
    # identity (where MFA does not). A stale or duplicated active key is the open
    # finding worth review.
    needs_rotation = stale or multiple_active
    return _event(
        account=account,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="access_key_hygiene",
        dedupe_key=user_name,
        event_type="aws.iam.access_key_hygiene",
        asset_id=f"aws:iam:user/{user_name}",
        asset_type="identity_account",
        controls=ACCESS_KEY_CONTROLS,
        status="open" if needs_rotation else "pass",
        severity="medium" if needs_rotation else "info",
        evidence_ref=f"{arn}/access-keys",
        attributes={
            "user_name": user_name,
            "identity_type": classify_identity_type(console_access=console_access),
            "active_key_count": len(active),
            "oldest_active_key_age_days": oldest,
            "key_rotation_sla_days": MAX_ACCESS_KEY_AGE_DAYS,
            "stale_key": stale,
            "multiple_active_keys": multiple_active,
            "needs_rotation": needs_rotation,
        },
    )


def _policy_event(
    account: str,
    policy: dict[str, Any],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any]:
    has_policy = bool(policy)
    weaknesses = _password_policy_weaknesses(policy)
    strong = has_policy and not weaknesses
    if not has_policy:
        status, severity = "open", "high"
    elif strong:
        status, severity = "pass", "info"
    else:
        status, severity = "open", "medium"
    return _event(
        account=account,
        collected_at=collected_at,
        tenant_id=tenant_id,
        signal="password_policy",
        dedupe_key="account-password-policy",
        event_type="aws.iam.password_policy",
        asset_id=f"aws:account:{account}",
        asset_type="account_config",
        controls=POLICY_CONTROLS,
        status=status,
        severity=severity,
        evidence_ref=f"arn:aws:iam::{account}:account-password-policy",
        attributes={
            "account_id": account,
            "password_policy_present": has_policy,
            "password_policy_strong": strong,
            "minimum_password_length": policy.get("MinimumPasswordLength"),
            "require_symbols": policy.get("RequireSymbols"),
            "require_numbers": policy.get("RequireNumbers"),
            "require_uppercase": policy.get("RequireUppercaseCharacters"),
            "require_lowercase": policy.get("RequireLowercaseCharacters"),
            "weaknesses": weaknesses,
        },
    )


def _password_policy_weaknesses(policy: dict[str, Any]) -> list[str]:
    if not policy:
        return ["no_password_policy"]
    weaknesses: list[str] = []
    length = policy.get("MinimumPasswordLength")
    if not isinstance(length, int) or length < MIN_PASSWORD_LENGTH:
        weaknesses.append("minimum_password_length_below_14")
    if not policy.get("RequireSymbols"):
        weaknesses.append("symbols_not_required")
    if not policy.get("RequireNumbers"):
        weaknesses.append("numbers_not_required")
    if not policy.get("RequireUppercaseCharacters"):
        weaknesses.append("uppercase_not_required")
    if not policy.get("RequireLowercaseCharacters"):
        weaknesses.append("lowercase_not_required")
    return weaknesses


def _event(
    *,
    account: str,
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
    stable = _stable_suffix(account=account, signal=signal, asset_id=asset_id, dedupe_key=dedupe_key)
    return {
        "event_id": f"aws-{stable}",
        "tenant_id": tenant_id,
        "workspace_id": "default",
        "event_time": utc_iso(collected_at),
        "source": "aws",
        "event_type": event_type,
        "entity": {
            "asset_id": asset_id,
            "asset_type": asset_type,
            "asset_owner": account,
            "environment": "prod",
            "org": account,
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


def _iso_or_none(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return utc_iso(value)
    return str(value)


def _account_slug(account_id: str) -> str:
    slug = re.sub(r"[^a-z0-9_.:-]+", "-", str(account_id).lower()).strip("-")
    return slug or "aws-account"


def _stable_suffix(*, account: str, signal: str, asset_id: str, dedupe_key: str | None) -> str:
    """Build a deterministic connector-local id without hashing identity data.

    The pipeline computes the canonical raw evidence hash after collection. These
    IDs only need to be stable for connector upserts and evidence-room links.
    """
    return stable_id_slug(f"{account}:{signal}:{dedupe_key or asset_id}", fallback="aws")
