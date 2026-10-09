"""S3 object-storage evidence collector.

Read-only LIST/HEAD against an evidence prefix in a customer's S3 bucket.
Emits one raw evidence row per object (SARIF, JSON, attestation, audit export)
so snapshot-mode sync can replace the current prefix inventory.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.connector_controls import mapped_controls
from security_lakehouse.connector_ids import stable_id_slug
from security_lakehouse.delegation import require_aws_delegation, server_env_override
from security_lakehouse.io import read_json
from security_lakehouse.models import parse_event_time, utc_iso
from security_lakehouse.runtime_environment import runtime_env

CONNECTOR_ID = "object-storage-evidence"
SOURCE = "s3"
DEFAULT_CONTROLS = ["SOC2-CC6.1", "ISO27001-A.5.15"]
EVIDENCE_SUFFIXES = (".json", ".sarif", ".jsonl", ".ndjson")


class S3Client:
    """Read-only S3 client backed by ``boto3``."""

    def __init__(
        self,
        *,
        bucket: str,
        prefix: str,
        region_name: str | None = None,
        role_arn: str | None = None,
        external_id: str | None = None,
        session_name: str = "trustops-object-storage",
    ) -> None:
        require_aws_delegation(role_arn, external_id, label="object-storage-evidence")
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover - live S3 only
            raise RuntimeError(
                "object-storage-evidence live collection requires boto3; install it or use --fixture-dir"
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
            self._s3 = session.client("s3")
        else:
            self._s3 = boto3.client("s3", region_name=region_name)
        self.bucket = bucket
        self.prefix = _normalize_prefix(prefix)

    def list_objects(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        paginator = self._s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for item in page.get("Contents") or []:
                key = str(item.get("Key") or "").strip()
                if not key or key.endswith("/"):
                    continue
                if not _is_evidence_key(key):
                    continue
                rows.append(
                    {
                        "key": key,
                        "size": int(item.get("Size") or 0),
                        "etag": str(item.get("ETag") or "").strip('"'),
                        "last_modified": item.get("LastModified"),
                    }
                )
        return rows

    def probe(self) -> dict[str, Any]:
        try:
            rows = self.list_objects()
            return {
                "ok": True,
                "bucket": self.bucket,
                "prefix": self.prefix,
                "object_count": len(rows),
                "error": None,
            }
        except Exception as exc:  # noqa: BLE001 - probe surfaces sanitized errors
            return {
                "ok": False,
                "bucket": self.bucket,
                "prefix": self.prefix,
                "object_count": None,
                "error": exc.__class__.__name__,
            }

    def discover_scope(self) -> dict[str, Any]:
        prefixes = self._common_prefixes()
        selected = self.prefix or (prefixes[0] if prefixes else "")
        selectors = [
            {"kind": "bucket", "name": self.bucket, "required": True, "selected": True},
            *[
                {
                    "kind": "prefix",
                    "name": name,
                    "required": False,
                    "selected": bool(selected and name == selected),
                }
                for name in prefixes
            ],
        ]
        if selected and selected not in prefixes:
            selectors.append(
                {"kind": "prefix", "name": selected, "required": True, "selected": True},
            )
        return {
            "ok": True,
            "selection_mode": "visible_prefixes",
            "selectors": selectors,
            "recommended_options": {"bucket": self.bucket, "prefix": selected},
        }

    def _common_prefixes(self) -> list[str]:
        prefixes: list[str] = []
        paginator = self._s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Delimiter="/"):
            for entry in page.get("CommonPrefixes") or []:
                prefix = str(entry.get("Prefix") or "").strip()
                if prefix:
                    prefixes.append(prefix)
        return sorted(prefixes)


class S3FixtureClient:
    """Offline S3 evidence client backed by a fixture manifest."""

    def __init__(self, fixture_dir: str | Path, *, bucket: str = "trustops-evidence") -> None:
        self.fixture = Path(fixture_dir)
        self.bucket = bucket
        manifest = read_json(self.fixture / "manifest.json")
        self.objects = [row for row in manifest if isinstance(row, dict)] if isinstance(manifest, list) else []

    def list_objects(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.objects]

    def probe(self) -> dict[str, Any]:
        rows = self.list_objects()
        prefix = _common_prefix([str(row.get("key") or "") for row in rows])
        return {
            "ok": True,
            "bucket": self.bucket,
            "prefix": prefix,
            "object_count": len(rows),
            "error": None,
        }

    def discover_scope(self) -> dict[str, Any]:
        keys = [str(row.get("key") or "") for row in self.objects]
        prefix = _common_prefix(keys)
        prefixes = sorted({f"{part}/" for key in keys for part in [_prefix_before_filename(key)] if part})
        selectors = [
            {"kind": "bucket", "name": self.bucket, "required": True, "selected": True},
            *[{"kind": "prefix", "name": name, "required": False, "selected": name == prefix} for name in prefixes],
        ]
        return {
            "ok": True,
            "selection_mode": "visible_prefixes",
            "selectors": selectors,
            "recommended_options": {"bucket": self.bucket, "prefix": prefix},
        }


def collect_s3_evidence(
    client: S3Client | S3FixtureClient,
    *,
    bucket: str | None = None,
    prefix: str | None = None,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    """Collect canonical raw evidence rows from S3 object metadata."""
    now = collected_at or datetime.now(UTC)
    bucket_name = bucket or client.bucket
    scope_prefix = prefix or str(getattr(client, "prefix", ""))
    rows: list[dict[str, Any]] = []
    for item in client.list_objects():
        event = _object_event(item, bucket=bucket_name, prefix=scope_prefix, collected_at=now, tenant_id=tenant_id)
        if event is not None:
            rows.append(event)
    return rows


def probe_s3_access(
    *,
    credentials: dict[str, Any],
    options: dict[str, Any],
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    env = runtime_env(env)
    bucket, prefix, region, role_arn, external_id = _connection_params(credentials, options, env=env)
    if not bucket:
        raise ValueError("object-storage-evidence probe requires bucket")
    return S3Client(
        bucket=bucket,
        prefix=prefix,
        region_name=region,
        role_arn=role_arn,
        external_id=external_id,
    ).probe()


def discover_s3_scope(
    *,
    credentials: dict[str, Any],
    options: dict[str, Any],
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    env = runtime_env(env)
    bucket, prefix, region, role_arn, external_id = _connection_params(credentials, options, env=env)
    if not bucket:
        return {"ok": False, "error": "bucket is required", "selectors": []}
    try:
        client = S3Client(
            bucket=bucket,
            prefix=prefix,
            region_name=region,
            role_arn=role_arn,
            external_id=external_id,
        )
        return client.discover_scope()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": exc.__class__.__name__, "selectors": []}


def _connection_params(
    credentials: dict[str, Any],
    options: dict[str, Any],
    *,
    env: dict[str, str] | None = None,
) -> tuple[str, str, str | None, str | None, str | None]:
    env = runtime_env(env)
    environment = env or {}
    bucket = str(options.get("bucket") or credentials.get("bucket") or "").strip()
    prefix = _normalize_prefix(str(options.get("prefix") or credentials.get("prefix") or ""))
    region = (
        str(options.get("region") or credentials.get("region") or environment.get("AWS_REGION") or "").strip() or None
    )
    role_arn = (
        str(credentials.get("role_arn") or server_env_override(environment.get("AWS_ROLE_ARN")) or "").strip() or None
    )
    external_id = (
        str(credentials.get("external_id") or server_env_override(environment.get("AWS_EXTERNAL_ID")) or "").strip()
        or None
    )
    return bucket, prefix, region, role_arn, external_id


def _object_event(
    item: dict[str, Any],
    *,
    bucket: str,
    prefix: str,
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any] | None:
    key = str(item.get("key") or "").strip()
    if not key:
        return None
    bundle_id = str(item.get("bundle_id") or _bundle_id_from_key(key))
    evidence_type = str(item.get("evidence_type") or _evidence_type_from_key(key))
    status = _status(item.get("status"))
    severity = _severity(item.get("severity") or ("medium" if status == "open" else "info"))
    hash_sha256 = str(item.get("hash_sha256") or item.get("etag") or "").strip() or None
    event_time = _event_time_iso(item.get("last_modified"), fallback=collected_at)
    stable = _slug(f"{bucket}:{key}")
    controls = _controls(item, DEFAULT_CONTROLS)
    return {
        "event_id": f"s3-{stable}",
        "tenant_id": tenant_id,
        "workspace_id": "default",
        "event_time": event_time,
        "source": SOURCE,
        "event_type": f"s3.evidence.{evidence_type}",
        "entity": {
            "asset_id": f"s3://{bucket}/{key}",
            "asset_type": "evidence_object",
            "asset_owner": str(item.get("owner") or "security-platform"),
            "environment": str(item.get("environment") or "prod"),
            "org": bucket,
        },
        "severity": severity,
        "status": status,
        "controls": controls,
        "evidence": {
            "evidence_id": f"ev-{stable}",
            "evidence_ref": f"s3://{bucket}/{key}",
            "evidence_collected_at": utc_iso(collected_at),
        },
        "attributes": {
            "bucket": bucket,
            "prefix": prefix,
            "key": key,
            "bundle_id": bundle_id,
            "evidence_type": evidence_type,
            "size": item.get("size"),
            "etag": item.get("etag"),
            "hash_sha256": hash_sha256,
        },
    }


def _controls(row: dict[str, Any], default: list[str]) -> list[str]:
    return mapped_controls(row, default)


def _status(value: Any) -> str:
    text = str(value or "observed").strip().lower()
    if text in {"pass", "passed", "ok", "ready", "compliant", "closed", "resolved"}:
        return "pass"
    if text in {"fail", "failed", "failing", "blocked", "open", "noncompliant", "non-compliant"}:
        return "open"
    return "observed"


def _severity(value: Any) -> str:
    text = str(value or "info").strip().lower()
    if text in {"critical", "high", "medium", "low", "info", "none"}:
        return text
    return "info"


def _event_time_iso(value: Any, *, fallback: datetime) -> str:
    if value is None:
        return utc_iso(fallback)
    if isinstance(value, datetime):
        return utc_iso(value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC))
    text = str(value).strip()
    if not text:
        return utc_iso(fallback)
    try:
        return utc_iso(parse_event_time(text))
    except ValueError:
        return text.replace(" ", "T") + ("Z" if not text.endswith("Z") and "+" not in text else "")


def _bundle_id_from_key(key: str) -> str:
    name = key.rsplit("/", 1)[-1]
    for suffix in EVIDENCE_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _evidence_type_from_key(key: str) -> str:
    lowered = key.lower()
    if lowered.endswith(".sarif"):
        return "sarif"
    if lowered.endswith(".jsonl") or lowered.endswith(".ndjson"):
        return "audit_export"
    if "attestation" in lowered:
        return "attestation"
    return "json"


def _is_evidence_key(key: str) -> bool:
    lowered = key.lower()
    return lowered.endswith(EVIDENCE_SUFFIXES)


def _normalize_prefix(prefix: str) -> str:
    text = str(prefix or "").strip()
    if text and not text.endswith("/"):
        text += "/"
    return text


def _common_prefix(keys: list[str]) -> str:
    if not keys:
        return ""
    parts = [key.split("/") for key in keys if key]
    if not parts:
        return ""
    shared: list[str] = []
    for segment_group in zip(*parts, strict=False):
        if len(set(segment_group)) == 1:
            shared.append(segment_group[0])
        else:
            break
    if not shared:
        return ""
    return "/".join(shared[:-1] + [""]) if len(shared) > 1 else f"{shared[0]}/"


def _prefix_before_filename(key: str) -> str:
    if "/" not in key:
        return ""
    return key.rsplit("/", 1)[0] + "/"


_S3_UNSAFE = re.compile(r"[^a-z0-9_.:@/-]+")


def _slug(value: str) -> str:
    return stable_id_slug(value, fallback="s3", unsafe=_S3_UNSAFE)
