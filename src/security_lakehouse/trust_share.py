"""Scoped, revocable, expiring share links for the Trust Center.

The Trust Center is the surface external reviewers (auditors, customers,
prospects) use to verify posture without internal-team-grade access. A
share is a signed token tied to:

  * ``role``     — auditor (read-only, owner/assignee fields redacted)
  * ``scope``    — what subset of posture is visible (full or one framework)
  * ``expires_at``
  * ``created_by``

The share table is append-only at ``gold/trust_shares.jsonl``. Revoke
appends a new record with ``revoked_at``. Only the token *hash* is stored;
the raw token returns once at create time.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from security_lakehouse import strict_json, tenancy
from security_lakehouse.data_policy import SENSITIVITY_LEVELS, normalize_sensitivity
from security_lakehouse.io import append_jsonl
from security_lakehouse.models import instant_sort_key

ALLOWED_ROLES = {"auditor"}
ALLOWED_SCOPES = {"posture_full", "posture_framework"}
ALLOWED_SENSITIVITY_CEILINGS = set(SENSITIVITY_LEVELS)

SHARES_FILE = "trust_shares.jsonl"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _gold(lake_dir: str | Path) -> Path:
    return Path(lake_dir) / "gold"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_share(
    lake_dir: str | Path,
    *,
    role: str,
    scope: str = "posture_full",
    expires_in_hours: int = 24,
    created_by: str = "console",
    framework_id: str | None = None,
    sensitivity_ceiling: str = "public",
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    """Issue a new share. Returns the raw token (only once) and the record."""
    if role not in ALLOWED_ROLES:
        raise ValueError(f"role must be one of {sorted(ALLOWED_ROLES)}")
    if scope not in ALLOWED_SCOPES:
        raise ValueError(f"scope must be one of {sorted(ALLOWED_SCOPES)}")
    if scope == "posture_framework":
        from security_lakehouse.catalog import load_framework_registry

        if not framework_id or framework_id not in load_framework_registry():
            raise ValueError("framework scope requires a known framework_id")
    sensitivity_ceiling = normalize_sensitivity(sensitivity_ceiling, default="")
    if sensitivity_ceiling not in ALLOWED_SENSITIVITY_CEILINGS:
        raise ValueError(f"sensitivity_ceiling must be one of {sorted(ALLOWED_SENSITIVITY_CEILINGS)}")
    if expires_in_hours <= 0 or expires_in_hours > 24 * 90:
        raise ValueError("expires_in_hours must be between 1 and 2160 (90 days)")
    idempotency_key = str(idempotency_key or "").strip() or None
    if idempotency_key:
        existing = _share_by_idempotency_key(lake_dir, idempotency_key)
        if existing is not None:
            return {**existing, "idempotent_replay": True}
    now = _utc_now()
    expires_at = now + timedelta(hours=expires_in_hours)
    token = "trust_" + secrets.token_urlsafe(24)
    share_id = secrets.token_urlsafe(8)
    record = {
        "share_id": share_id,
        "role": role,
        "scope": scope,
        "framework_id": framework_id,
        "sensitivity_ceiling": sensitivity_ceiling,
        "expires_at": _iso(expires_at),
        "created_by": created_by,
        "created_at": _iso(now),
        "revoked_at": None,
        "token_sha256": _hash_token(token),
    }
    if idempotency_key:
        record["idempotency_key"] = idempotency_key
    gold = _gold(lake_dir)
    gold.mkdir(parents=True, exist_ok=True)
    append_jsonl(gold / SHARES_FILE, record)
    return {**record, "token": token}


def _share_by_idempotency_key(lake_dir: str | Path, idempotency_key: str) -> dict[str, Any] | None:
    """Return the latest share created with ``idempotency_key``, if any."""
    matches = [
        row for row in list_shares(lake_dir, include_revoked=True) if row.get("idempotency_key") == idempotency_key
    ]
    return matches[0] if matches else None


def _parse_instant(value: object) -> datetime | None:
    """Parse an ISO timestamp as an aware UTC instant; a naive value is UTC."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _is_expired(expires_at: object, now: datetime) -> bool:
    if not expires_at:
        return False
    parsed = _parse_instant(expires_at)
    return parsed is None or parsed < now


def _read_share_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = strict_json.loads(line)
        if not isinstance(row, dict):
            raise strict_json.InvalidJSON("stored share must be a JSON object")
        rows.append(row)
    return rows


# Per-lake parse of the share file, keyed on its (mtime, size) so an append by
# any process (create or revoke) invalidates it. The public trust endpoint is
# unauthenticated and probes every tenant lake, so an unchanged file must cost a
# stat, not a full re-parse.
_SHARE_CACHE: dict[str, tuple[tuple[int, int], list[dict[str, Any]], dict[str, dict[str, Any]]]] = {}
_SHARE_CACHE_LOCK = threading.Lock()


def _latest_shares(lake_dir: str | Path) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Return (latest record per share_id, token hash -> latest record)."""
    path = _gold(lake_dir) / SHARES_FILE
    try:
        stat = path.stat()
    except FileNotFoundError:
        return [], {}
    key = str(path.resolve())
    version = (stat.st_mtime_ns, stat.st_size)
    with _SHARE_CACHE_LOCK:
        cached = _SHARE_CACHE.get(key)
        if cached is not None and cached[0] == version:
            return cached[1], cached[2]
    latest: dict[str, dict[str, Any]] = {}
    for row in _read_share_rows(path):
        sid = str(row.get("share_id") or "")
        if not sid:
            continue
        prev = latest.get(sid)
        if prev is None or instant_sort_key(row.get("created_at")) >= instant_sort_key(prev.get("created_at")):
            latest[sid] = row
    records = list(latest.values())
    by_token = {str(r["token_sha256"]): r for r in records if r.get("token_sha256")}
    with _SHARE_CACHE_LOCK:
        _SHARE_CACHE[key] = (version, records, by_token)
    return records, by_token


def list_shares(
    lake_dir: str | Path, *, include_revoked: bool = False, additional_lakes: tuple[Path, ...] = ()
) -> list[dict[str, Any]]:
    """Return current shares from the lake and caller-authorized additional lakes."""
    records, _by_token = _latest_shares(lake_dir)
    rows = [dict(r) for r in records]
    for other in additional_lakes:
        if other.resolve() != Path(lake_dir).resolve():
            rows.extend(list_shares(other, include_revoked=include_revoked))
    if not include_revoked:
        rows = [r for r in rows if not r.get("revoked_at")]
    now = _utc_now()
    for row in rows:
        row["expired"] = _is_expired(row.get("expires_at"), now)
    rows.sort(key=lambda r: instant_sort_key(r.get("created_at")), reverse=True)
    return rows


def lake_search_paths(
    root: str | Path,
    *,
    tenant_ids: list[str] | None = None,
    bound_tenant: str | None = None,
) -> list[Path]:
    """Return lake directories to search for a trust share token (newest tenants first)."""
    root_path = Path(root)
    paths: list[Path] = []
    seen: set[Path] = set()

    def _add(candidate: Path) -> None:
        resolved = candidate.resolve()
        if resolved in seen:
            return
        seen.add(resolved)
        paths.append(candidate)

    if bound_tenant is not None:
        # tenant_lake picks the flat root or tenants/<bound>, whichever holds it.
        _add(tenancy.tenant_lake(root_path, bound_tenant, bound_tenant=bound_tenant))
    for tenant_id in sorted(tenant_ids or [], reverse=True):
        _add(tenancy.tenant_lake(root_path, tenant_id, bound_tenant=bound_tenant))
    # CLI-issued shares remain public before server tenants are provisioned.
    # Once tenants exist, the flat root must have an established owner.
    if (bound_tenant is not None or not tenant_ids) and tenancy.is_flat_lake(root_path):
        _add(root_path)
    return paths


def resolve_share_from_root(
    root: str | Path,
    token: str,
    *,
    tenant_ids: list[str] | None = None,
    bound_tenant: str | None = None,
) -> tuple[dict[str, Any], Path] | None:
    """Resolve a token against tenant-scoped lakes under ``root``.

    Returns the live share record and the lake directory that owns it, or
    ``None`` when the token is unknown, revoked, or expired in every candidate.
    """
    for lake_dir in lake_search_paths(root, tenant_ids=tenant_ids, bound_tenant=bound_tenant):
        share = resolve_share(lake_dir, token)
        if share is not None:
            return share, lake_dir
    return None


def resolve_share(lake_dir: str | Path, token: str) -> dict[str, Any] | None:
    """Resolve a raw token to its live share record, or ``None``.

    Hashes the presented token and returns the matching share only if it is
    neither revoked nor expired. Returns ``None`` for any miss so the caller
    can answer a generic 404 without leaking whether the token was unknown,
    revoked, or simply past its expiry.
    """
    if not token:
        return None
    _records, by_token = _latest_shares(lake_dir)
    record = by_token.get(_hash_token(token))
    if record is None or record.get("revoked_at"):
        return None
    if _is_expired(record.get("expires_at"), _utc_now()):
        return None
    return {**record, "expired": False}


def revoke_share(
    lake_dir: str | Path, share_id: str, *, actor: str = "console", additional_lakes: tuple[Path, ...] = ()
) -> dict[str, Any] | None:
    """Revoke in every caller-authorized lake so no copied record remains live."""
    additional_match = None
    for other in additional_lakes:
        if other.resolve() != Path(lake_dir).resolve():
            result = revoke_share(other, share_id, actor=actor)
            if result is not None:
                additional_match = result
    shares = list_shares(lake_dir, include_revoked=True)
    match = next((s for s in shares if s.get("share_id") == share_id), None)
    if match is None or match.get("revoked_at"):
        return match or additional_match
    revoked = {
        **match,
        "revoked_at": _iso(_utc_now()),
        "revoked_by": actor,
    }
    append_jsonl(_gold(lake_dir) / SHARES_FILE, revoked)
    return revoked
