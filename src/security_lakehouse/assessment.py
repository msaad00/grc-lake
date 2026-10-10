"""Continuous compliance assessment engine.

The security data lake pipeline creates evidence and analytics tables. This module turns
those artifacts into product-level assessment state:

- current posture: continuously refreshed answer to "are we compliant now?"
- point-in-time snapshot: immutable assessment export for audits or JIT reviews
- violations: control and asset failures requiring owner action
"""

from __future__ import annotations

import hashlib
import heapq
import json
import logging
import re
from collections import OrderedDict, defaultdict
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any

from security_lakehouse import strict_json
from security_lakehouse.connectors import DEFAULT_CONNECTOR_CATALOG, load_connector_catalog
from security_lakehouse.event_status import FAIL_STATUSES
from security_lakehouse.evidence_freshness import (
    STALE_STATUSES,
    build_evidence_freshness,
    freshness_records_with_sources,
    freshness_status_interval,
    stale_control_ids,
    summarize_source_freshness,
)
from security_lakehouse.evidence_provenance import contains_synthetic_evidence
from security_lakehouse.generations import generation_identity, generation_reader
from security_lakehouse.io import append_jsonl, file_version, iter_jsonl, read_json, read_jsonl, write_json
from security_lakehouse.ledger import chain_lock
from security_lakehouse.models import SEVERITY_SCORE, utc_iso
from security_lakehouse.read_cache import DerivedCache, copy_rows, input_versions, json_copy, rows_are_flat
from security_lakehouse.vocabulary import ControlVerdict

logger = logging.getLogger(__name__)

# Called after a snapshot is written (and the chain lock released) with
# ``(snapshot_path, assessment, new_violations, newly_failing_controls)``. See
# ``write_assessment_snapshot`` for how the diff arguments are derived.
SnapshotWrittenHook = Callable[[Path, dict[str, Any], list[dict[str, Any]], list[str]], None]

VIOLATION_STATUSES = FAIL_STATUSES

# Append-only ledger that chains every snapshot to its predecessor. Each line
# records (prev_hash -> assessment_hash); because assessment_hash covers
# prev_hash, mutating or dropping any historical snapshot breaks the chain.
SNAPSHOT_LEDGER = ("gold", "snapshots", "_ledger.jsonl")


class SnapshotIntegrityError(ValueError):
    """Persisted snapshot history failed validation and needs reconciliation."""


_POSTURE_INPUTS = (
    "silver/normalized_events.jsonl",
    "gold/control_posture.jsonl",
    "gold/control_tests.jsonl",
    "gold/asset_risk.jsonl",
    "bronze/raw_events.jsonl",
)
_STALE_EVIDENCE_SAMPLE = 50
# Highest-severity violations kept inline in a posture payload; counts, scores,
# and ``violation_summary.total_count`` still cover every violation.
INLINE_VIOLATION_CAP = 10_000
_POSTURE_WINDOWS: DerivedCache[_PostureWindow] = DerivedCache(max_entries=8, per_root=2)


def _utcnow() -> datetime:
    return datetime.now(UTC)


@generation_reader
def build_current_posture(
    lake_dir: str | Path,
    *,
    freshness_days: int = 7,
    now: datetime | None = None,
    max_violations: int | None = None,
    inline_violation_cap: int | None = INLINE_VIOLATION_CAP,
) -> dict[str, Any]:
    """Build the continuously refreshed compliance posture from lake artifacts.

    When ``max_violations`` is set, only the highest-severity violations are
    retained in the payload while aggregate counts still reflect the full lake.
    ``inline_violation_cap`` bounds the inline list the same way after scores
    and counts are computed from every violation; ``None`` keeps all of them
    for readers that list violations.

    A live read (no ``now``) reuses the posture computed from the same input
    file versions while no evidence row changes freshness status; only the
    evaluation time, the sampled stale evidence ages, and the hash are
    recomputed. Every call returns its own copy.
    """
    lake = Path(lake_dir)
    if now is not None:
        return _PostureWindow.build(
            lake, freshness_days, max_violations, now, inline_violation_cap=inline_violation_cap
        ).render(now)
    evaluated_at = _utcnow()
    version = (
        input_versions(lake, _POSTURE_INPUTS),
        file_version(DEFAULT_CONNECTOR_CATALOG),
        json.dumps(generation_identity(lake), sort_keys=True),
    )
    window = _POSTURE_WINDOWS.get(
        lake,
        ("current_posture", freshness_days, max_violations, inline_violation_cap),
        version,
        lambda: _PostureWindow.build(
            lake, freshness_days, max_violations, evaluated_at, inline_violation_cap=inline_violation_cap
        ),
        accept=lambda cached: cached.covers(evaluated_at),
    )
    return window.render(evaluated_at)


class _PostureWindow:
    """Posture for one input version over an interval with no freshness status change."""

    def __init__(
        self,
        *,
        head: dict[str, Any],
        tail: dict[str, Any],
        freshness: dict[str, Any],
        stale_sources: list[dict[str, Any]],
        connectors: dict[str, dict[str, Any]],
        default_slo_minutes: int,
        since: datetime | None,
        until: datetime | None,
    ) -> None:
        self.head = head
        self.tail = tail
        self.freshness = freshness
        self.stale_sources = stale_sources
        self.connectors = connectors
        self.default_slo_minutes = default_slo_minutes
        self.since = since
        self.until = until
        self.segments = {key: _canonical_bytes(value) for key, value in {**head, **tail}.items()}
        self.row_lists = {
            key: rows_are_flat(value)
            for key, value in tail.items()
            if isinstance(value, list) and all(isinstance(row, dict) for row in value)
        }

    def covers(self, moment: datetime) -> bool:
        return (self.since is None or self.since <= moment) and (self.until is None or moment < self.until)

    @classmethod
    def build(
        cls,
        lake: Path,
        freshness_days: int,
        max_violations: int | None,
        evaluated_at: datetime,
        *,
        inline_violation_cap: int | None = INLINE_VIOLATION_CAP,
    ) -> _PostureWindow:
        default_slo_minutes = freshness_days * 24 * 60
        connectors = load_connector_catalog()
        events = read_jsonl(lake / "silver" / "normalized_events.jsonl", missing_ok=True)
        controls = read_jsonl(lake / "gold" / "control_posture.jsonl", missing_ok=True)
        control_tests = read_jsonl(lake / "gold" / "control_tests.jsonl", missing_ok=True)
        assets = read_jsonl(lake / "gold" / "asset_risk.jsonl", missing_ok=True)
        asset_names = {
            str(row["asset_id"]): str(row["asset_name"])
            for row in assets
            if row.get("asset_id") and row.get("asset_name")
        }
        violations, violation_summary = build_violations(events, max_violations=max_violations, asset_names=asset_names)
        pairs = freshness_records_with_sources(
            events, now=evaluated_at, default_slo_minutes=default_slo_minutes, connectors=connectors
        )
        evidence_freshness = [record for record, _row in pairs]
        since, until = freshness_status_interval(evidence_freshness, evaluated_at)
        assessment = _assess_posture(
            lake,
            events=events,
            controls=controls,
            control_tests=control_tests,
            assets=assets,
            violations=violations,
            violation_summary=violation_summary,
            evidence_freshness=evidence_freshness,
            freshness_days=freshness_days,
            evaluated_at=evaluated_at,
            inline_violation_cap=inline_violation_cap,
        )
        stale_sources = [row for record, row in pairs if record["status"] in STALE_STATUSES]
        head_keys = ("schema_version", "assessment_type", "synthetic_fixture")
        dynamic = {"evaluated_at", "evidence_freshness", "assessment_hash"}
        return cls(
            head={key: assessment[key] for key in head_keys},
            tail={key: value for key, value in assessment.items() if key not in dynamic and key not in head_keys},
            freshness={
                key: value for key, value in assessment["evidence_freshness"].items() if key != "stale_evidence"
            },
            stale_sources=stale_sources[:_STALE_EVIDENCE_SAMPLE],
            connectors=connectors,
            default_slo_minutes=default_slo_minutes,
            since=since,
            until=until,
        )

    def render(self, evaluated_at: datetime) -> dict[str, Any]:
        stale_evidence = build_evidence_freshness(
            self.stale_sources,
            now=evaluated_at,
            default_slo_minutes=self.default_slo_minutes,
            connectors=self.connectors,
        )
        assessment: dict[str, Any] = json_copy(self.head)
        assessment["evaluated_at"] = utc_iso(evaluated_at)
        for key, value in self.tail.items():
            if key in self.row_lists:
                assessment[key] = copy_rows(value, flat=self.row_lists[key])
            else:
                assessment[key] = json_copy(value)
            if key == "stale_controls":
                assessment["evidence_freshness"] = {**json_copy(self.freshness), "stale_evidence": stale_evidence}
        digest = hashlib.sha256(b"{")
        for position, key in enumerate(sorted(assessment)):
            digest.update(b"," if position else b"")
            digest.update(_canonical_bytes(key) + b":")
            digest.update(self.segments.get(key) or _canonical_bytes(assessment[key]))
        digest.update(b"}")
        assessment["assessment_hash"] = digest.hexdigest()
        return assessment


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _assess_posture(
    lake: Path,
    *,
    events: list[dict[str, Any]],
    controls: list[dict[str, Any]],
    control_tests: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    violations: list[dict[str, Any]],
    violation_summary: dict[str, Any],
    evidence_freshness: list[dict[str, Any]],
    freshness_days: int,
    evaluated_at: datetime,
    inline_violation_cap: int | None = INLINE_VIOLATION_CAP,
) -> dict[str, Any]:
    stale_controls = stale_control_ids(
        evidence_freshness,
        required_types={
            str(row["control_id"]): list(row.get("required_evidence_types") or []) for row in control_tests
        },
    )
    evidenced_controls = {str(control_id) for row in evidence_freshness for control_id in row.get("control_ids", [])}
    stale_controls.update(
        str(row["control_id"]) for row in controls if str(row["control_id"]) not in evidenced_controls
    )
    stale_evidence = [row for row in evidence_freshness if row["status"] in {"stale", "expired", "missing"}]
    framework_scores = (
        _framework_scores_from_controls(controls, stale_controls)
        if violation_summary.get("truncated")
        else _framework_scores(controls, violations, stale_controls)
    )
    open_violations = [item for item in violations if item["state"] == "open"]
    severity_counts = violation_summary.get("severity_counts") or {}
    open_violation_count = int(violation_summary.get("total_count") or len(open_violations))
    critical_violation_count = int(
        severity_counts.get("critical") or sum(1 for item in open_violations if item["severity"] == "critical")
    )
    high_violation_count = int(
        severity_counts.get("high") or sum(1 for item in open_violations if item["severity"] == "high")
    )
    failed_control_tests = [item for item in control_tests if str(item.get("result", "")).lower() == "fail"]
    warning_control_tests = [item for item in control_tests if str(item.get("result", "")).lower() == "warn"]
    posture_score = _weighted_posture_score(framework_scores)
    critical_for_state = critical_violation_count > 0
    unevaluated = {str(row["control_id"]) for row in controls if row.get("status") == ControlVerdict.NOT_EVALUATED}
    if inline_violation_cap is not None and len(open_violations) > inline_violation_cap:
        open_violations, violation_summary = _cap_inline_violations(
            open_violations, violation_summary, inline_violation_cap
        )
    assessment = {
        "schema_version": "trustops.assessment.v1",
        "assessment_type": "current_posture",
        "synthetic_fixture": contains_synthetic_evidence(lake, events),
        "evaluated_at": utc_iso(evaluated_at),
        "freshness_days": freshness_days,
        "posture": {
            "score": posture_score,
            "scoring_version": "trustops.assessment_scoring.v2",
            "score_scope": "observed_controls",
            "state": (
                _posture_state(posture_score, critical_for_state, stale_controls | unevaluated)
                if controls
                else "not_evaluated"
            ),
            "framework_count": len(framework_scores),
            "control_count": len(controls),
            "asset_count": len(assets),
            "open_violation_count": open_violation_count,
            "critical_violation_count": critical_violation_count,
            "high_violation_count": high_violation_count,
            "failed_control_test_count": len(failed_control_tests),
            "warning_control_test_count": len(warning_control_tests),
            "stale_control_count": len(stale_controls),
            "not_evaluated_control_count": len(unevaluated),
            "stale_evidence_count": len(stale_evidence),
        },
        "frameworks": framework_scores,
        "violations": open_violations,
        "violation_summary": violation_summary,
        "top_risk_assets": assets[:10],
        "stale_controls": sorted(stale_controls),
        "evidence_freshness": {
            "count": len(evidence_freshness),
            "stale_count": len(stale_evidence),
            "sources": summarize_source_freshness(evidence_freshness),
            "stale_evidence": stale_evidence[:_STALE_EVIDENCE_SAMPLE],
        },
    }
    generation = generation_identity(lake)
    if generation is not None:
        assessment["generation"] = generation
    return assessment


def write_current_posture(lake_dir: str | Path, *, freshness_days: int = 7, max_violations: int | None = None) -> Path:
    """Write current posture into the gold zone."""
    lake = Path(lake_dir)
    output = lake / "gold" / "current_posture.json"
    cap = max_violations
    if cap is None:
        from security_lakehouse.io import count_jsonl

        silver_count = count_jsonl(lake / "silver" / "normalized_events.jsonl", missing_ok=True, base_dir=lake)
        if silver_count > 100_000:
            cap = 10_000
    write_json(output, build_current_posture(lake, freshness_days=freshness_days, now=_utcnow(), max_violations=cap))
    return output


def _catalog_bundle_for_snapshot() -> dict[str, Any] | None:
    """Return the active catalog bundle, or None if no catalog is reachable.

    Snapshots taken in bare test lakes without a control catalog still succeed;
    they just record a null bundle rather than failing the freeze.
    """
    try:
        from security_lakehouse.catalog_versions import bundle_summary

        return bundle_summary()
    except (OSError, ValueError, KeyError):
        return None


def _ledger_path(lake_dir: str | Path) -> Path:
    return Path(lake_dir).joinpath(*SNAPSHOT_LEDGER)


def _chain_tip(lake_dir: str | Path) -> str | None:
    """Return the assessment_hash of the most recent ledgered snapshot.

    The ledger — not file mtime or ``evaluated_at`` — is the chain's source of
    truth, so two snapshots sharing a timestamp still chain deterministically.
    """
    entries = read_jsonl(_ledger_path(lake_dir), missing_ok=True)
    return entries[-1].get("assessment_hash") if entries else None


def _prior_snapshot_payload(lake_dir: str | Path) -> dict[str, Any] | None:
    """Best-effort load of the most recently ledgered snapshot's full payload.

    Read-only and additive: used only to diff violations for webhook event
    detection (see :func:`_diff_violations`), never to decide the hash chain
    itself. A missing/unreadable prior snapshot yields ``None`` rather than
    raising, so a corrupt or pruned history never blocks a new snapshot write
    -- but unlike the genuine "this is the first snapshot ever" case (an empty
    ledger, which also returns ``None``), that outcome is silent data loss for
    the diff (every violation open since before the gap will never fire
    ``finding.created``/``control.failed``), so it is logged at warning level
    to make the failure observable instead of indistinguishable from "no gap."
    """
    entries = read_jsonl(_ledger_path(lake_dir), missing_ok=True)
    if not entries:
        return None
    name = entries[-1].get("snapshot")
    if not isinstance(name, str) or not name:
        logger.warning("prior snapshot read failed for %s: ledger's last entry has no snapshot filename", lake_dir)
        return None
    path = Path(lake_dir) / "gold" / "snapshots" / name
    if not path.is_file():
        logger.warning("prior snapshot read failed for %s: %s is missing (ledger entry points to it)", lake_dir, path)
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("prior snapshot read failed for %s: %s is unreadable (%s)", lake_dir, path, exc)
        return None
    if not isinstance(payload, dict):
        logger.warning("prior snapshot read failed for %s: %s did not contain a JSON object", lake_dir, path)
        return None
    return payload


def _diff_violations(prior: dict[str, Any] | None, current: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    """Return ``(new_violations, newly_failing_control_ids)`` between two snapshots.

    A violation is "new" when its ``violation_id`` is not present in the prior
    snapshot's open-violations list. A control is "newly failing" when it had
    zero open violations in the prior snapshot but at least one new violation
    in this one — a real transition derived from the two most recent
    point-in-time snapshots, not a fabricated one. There is no prior snapshot
    on the very first freeze of a lake, so nothing is reported as "new" then
    (everything open at that point is the starting state, not a transition).

    Defensive against malformed rows (e.g. a ``violation_id``/``control_id``
    that is not a string -- an unhashable value like a list would otherwise
    raise ``TypeError`` on set membership and break every caller of
    :func:`write_assessment_snapshot`, webhook-unaware ones included, since
    this runs inside the chain lock). Only string ids are ever added to the
    dedup sets; a violation whose id cannot be matched against the prior
    snapshot is conservatively treated as new rather than silently dropped or
    raising.
    """
    if prior is None:
        return [], []
    prior_violations = prior.get("violations")
    prior_ids: set[str] = set()
    prior_failing_controls: set[str] = set()
    if isinstance(prior_violations, list):
        for row in prior_violations:
            if not isinstance(row, dict):
                continue
            violation_id = row.get("violation_id")
            if isinstance(violation_id, str):
                prior_ids.add(violation_id)
            control_id = row.get("control_id")
            if isinstance(control_id, str):
                prior_failing_controls.add(control_id)
    current_violations = current.get("violations")
    if not isinstance(current_violations, list):
        return [], []
    new_violations: list[dict[str, Any]] = []
    for row in current_violations:
        if not isinstance(row, dict):
            continue
        violation_id = row.get("violation_id")
        if isinstance(violation_id, str) and violation_id in prior_ids:
            continue  # present in the prior snapshot too -- not new
        new_violations.append(row)
    newly_failing_controls = sorted(
        {
            row["control_id"]
            for row in new_violations
            if isinstance(row.get("control_id"), str) and row["control_id"] not in prior_failing_controls
        }
    )
    return new_violations, newly_failing_controls


@generation_reader
def write_assessment_snapshot(
    lake_dir: str | Path,
    *,
    output: str | Path | None = None,
    freshness_days: int = 7,
    reason: str = "manual",
    on_snapshot_written: SnapshotWrittenHook | None = None,
) -> Path:
    """Write a point-in-time assessment snapshot for audit/JIT review.

    Each snapshot is linked to its predecessor via ``prev_hash`` and recorded
    in an append-only ledger, so a snapshot that is later mutated or deleted is
    detectable by :func:`verify_snapshot_chain`.

    ``on_snapshot_written``, when given, is invoked *after* the chain lock is
    released with the new snapshot plus a violations diff against the prior
    snapshot (see :func:`_diff_violations`) — the hook point event-driven
    callers (e.g. the webhook dispatcher) use to push ``assessment.completed``,
    ``finding.created``, and ``control.failed`` notifications without this
    module taking on any DB/tenant/transport dependency itself. A failing hook
    is logged and swallowed, never allowed to turn a successful snapshot write
    into a caller-visible error.
    """
    lake = Path(lake_dir)
    # Concurrent snapshot requests must not read the same chain tip: serialize
    # the tip-read through ledger-append span so the chain can never fork.
    with chain_lock(_ledger_path(lake)):
        recovery_pending = lake / "gold/snapshot_recovery/pending.json"
        if recovery_pending.exists() or recovery_pending.is_symlink():
            raise SnapshotIntegrityError("snapshot recovery is pending; rerun reconcile-snapshots")
        if not _snapshot_chain_rows_unlocked(lake.resolve(), metadata_only=True)[1]["ok"]:
            raise SnapshotIntegrityError("snapshot integrity verification failed; history requires reconciliation")
        prev_hash = _chain_tip(lake)
        prior_payload = _prior_snapshot_payload(lake)
        # A snapshot is the audit record: freeze every violation, not the inline sample.
        assessment = build_current_posture(lake, freshness_days=freshness_days, inline_violation_cap=None)
        assessment["assessment_type"] = "point_in_time_snapshot"
        assessment["snapshot_reason"] = reason
        # Legacy lakes have no retained generation to resolve later. Freeze
        # their detail too; the content hash below covers these rows.
        assessment["control_posture"] = read_jsonl(lake / "gold" / "control_posture.jsonl", missing_ok=True)
        # Pin the catalog bundle (framework + control versions in force) so this
        # audit reproduces against the exact controls it was evaluated with. The
        # bundle is covered by assessment_hash below, so it is tamper-evident too.
        bundle_path = lake / "catalog" / "bundle.json"
        assessment["catalog_bundle"] = (
            read_json(bundle_path) if bundle_path.is_file() else _catalog_bundle_for_snapshot()
        )
        # Pin the mapping-review counts and the org decision-log tip, so the
        # coverage an auditor sees ties back to the decisions in force.
        from security_lakehouse.mapping_review import review_attestation

        assessment["mapping_review"] = review_attestation(lake)
        assessment["prev_hash"] = prev_hash
        # assessment_hash covers prev_hash, so the chain is tamper-evident.
        assessment["assessment_hash"] = _assessment_hash(assessment)
        ts = assessment["evaluated_at"].replace(":", "").replace("-", "")
        short = assessment["assessment_hash"][:12]
        snapshots_dir = lake / "gold/snapshots"
        storage_path = snapshots_dir / f"assessment-{ts}-{short}.json"
        output_path = Path(output) if output is not None else storage_path
        if output_path.parent.resolve() == snapshots_dir.resolve():
            if not _is_safe_snapshot_token(output_path.name) or not output_path.name.endswith(".json"):
                raise ValueError("snapshot filename must be a safe JSON filename")
            storage_path = output_path
        for target in {storage_path, output_path}:
            if target.exists() or target.is_symlink():
                raise FileExistsError(f"snapshot already exists, refusing to overwrite: {target}")
        write_json(storage_path, assessment)
        if output_path != storage_path:
            try:
                write_json(output_path, assessment)
            except Exception:
                storage_path.unlink()
                raise
        append_jsonl(
            _ledger_path(lake),
            {
                "evaluated_at": assessment["evaluated_at"],
                "snapshot": storage_path.name,
                "prev_hash": prev_hash,
                "assessment_hash": assessment["assessment_hash"],
                "snapshot_reason": reason,
                "recorded_at": utc_iso(datetime.now(UTC)),
            },
        )
        try:
            new_violations, newly_failing_controls = _diff_violations(prior_payload, assessment)
        except Exception:  # the diff is a defensive best-effort add-on, never allowed to break a snapshot write
            logger.exception("violations diff failed for %s; webhook finding/control events will not fire", output_path)
            new_violations, newly_failing_controls = [], []
    # Lock released above -- the hook (and any outbound webhook delivery it
    # triggers) must never hold up a concurrent writer.
    if on_snapshot_written is not None:
        try:
            on_snapshot_written(output_path, assessment, new_violations, newly_failing_controls)
        except Exception:  # a hook failure must never fail a successful snapshot write
            logger.exception("on_snapshot_written hook failed for %s", output_path)
    return output_path


# Cache only successful verification metadata, never mutable payload objects or
# filesystem timestamps. Every lookup hashes fresh bytes from every chain file.
_SNAPSHOT_CACHE_LIMIT = 4096
_verified_snapshot_bytes: OrderedDict[tuple[bytes, str, str | None, str], None] = OrderedDict()
_snapshot_cache_lock = Lock()


def _verified_snapshot_payload(path: Path, entry: dict[str, Any], *, include_payload: bool) -> dict[str, Any] | None:
    recorded_hash, previous, stamp = entry.get("assessment_hash"), entry.get("prev_hash"), entry.get("evaluated_at")
    if (
        not isinstance(recorded_hash, str)
        or len(recorded_hash) != 64
        or (previous is not None and (not isinstance(previous, str) or len(previous) != 64))
        or not isinstance(stamp, str)
    ):
        raise ValueError("invalid snapshot ledger metadata")
    _parse_iso(stamp)
    raw = path.read_bytes()
    key = (hashlib.sha256(raw).digest(), recorded_hash, previous, stamp)
    with _snapshot_cache_lock:
        cached = key in _verified_snapshot_bytes
        if cached:
            _verified_snapshot_bytes.move_to_end(key)
    if cached:
        # These exact bytes already passed strict decoding and canonical hashing.
        # A fresh object prevents a caller from mutating another reader's result.
        return json.loads(raw) if include_payload else None
    payload = strict_json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("snapshot must be an object")
    if _assessment_hash(payload) != recorded_hash or payload.get("assessment_hash") != recorded_hash:
        raise SnapshotIntegrityError("content hash does not match the ledger")
    if payload.get("prev_hash") != previous:
        raise SnapshotIntegrityError("payload prev_hash differs from ledger")
    if payload.get("evaluated_at") != stamp:
        raise SnapshotIntegrityError("snapshot timestamp differs from ledger")
    with _snapshot_cache_lock:
        _verified_snapshot_bytes[key] = None
        _verified_snapshot_bytes.move_to_end(key)
        while len(_verified_snapshot_bytes) > _SNAPSHOT_CACHE_LIMIT:
            _verified_snapshot_bytes.popitem(last=False)
    return payload if include_payload else None


def _snapshot_chain_rows(
    lake: Path, *, limit: int | None = None, snapshot_id: str | None = None, metadata_only: bool = False
) -> tuple[list[tuple[datetime, dict[str, Any], Path]], dict[str, Any]]:
    """Verify the whole chain, retaining payloads only for the selected rows."""
    snapshots_dir = lake / "gold/snapshots"
    if not snapshots_dir.exists():
        return [], {"ok": True, "length": 0, "issues": []}
    with chain_lock(_ledger_path(lake), shared=True):
        return _snapshot_chain_rows_unlocked(lake, limit=limit, snapshot_id=snapshot_id, metadata_only=metadata_only)


def _snapshot_chain_rows_unlocked(
    lake: Path,
    *,
    limit: int | None = None,
    snapshot_id: str | None = None,
    metadata_only: bool = False,
    allow_unledgered: bool = False,
) -> tuple[list[tuple[datetime, dict[str, Any], Path]], dict[str, Any]]:
    snapshots_dir = lake / "gold/snapshots"
    issues: list[str] = []
    rows: list[tuple[datetime, dict[str, Any], Path]] = []
    if snapshots_dir.resolve() != snapshots_dir.absolute() or _ledger_path(lake).is_symlink():
        return [], {"ok": False, "length": 0, "issues": ["invalid snapshot directory or ledger path"]}
    try:
        entries = read_jsonl(_ledger_path(lake), missing_ok=True)
    except (ValueError, OSError):
        return [], {"ok": False, "length": 0, "issues": ["snapshot ledger is unreadable"]}
    selected = set(range(len(entries)))
    if limit is not None and limit > 0:
        try:
            ordered = sorted(range(len(entries)), key=lambda index: _parse_iso(entries[index]["evaluated_at"]))
            selected = set(ordered[-limit:])
        except (ValueError, KeyError, TypeError, AttributeError):
            return [], {"ok": False, "length": len(entries), "issues": ["invalid snapshot timestamp"]}
    if snapshot_id is not None:
        selected = {
            index
            for index, entry in enumerate(entries)
            if isinstance(entry, dict)
            and (
                (isinstance(entry.get("snapshot"), str) and Path(entry["snapshot"]).stem == snapshot_id)
                or (isinstance(entry.get("assessment_hash"), str) and entry["assessment_hash"].startswith(snapshot_id))
            )
        }
    expected_prev: str | None = None
    names: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            issues.append(f"entry {index}: invalid ledger record")
            continue
        name = entry.get("snapshot")
        recorded_hash = entry.get("assessment_hash")
        if entry.get("prev_hash") != expected_prev:
            issues.append(f"entry {index}: prev_hash breaks the chain")
        if (
            not isinstance(name, str)
            or not _is_safe_snapshot_token(name)
            or not name.endswith(".json")
            or name in names
        ):
            issues.append(f"entry {index}: invalid or duplicate snapshot path")
            continue
        names.add(name)
        path = snapshots_dir / name
        if path.is_symlink() or not path.is_file():
            issues.append(f"entry {index}: snapshot file is missing or unsafe")
            expected_prev = recorded_hash
            continue
        try:
            payload = _verified_snapshot_payload(path, entry, include_payload=index in selected and not metadata_only)
            if index in selected:
                if metadata_only:
                    payload = {"evaluated_at": entry["evaluated_at"]}
                assert payload is not None
                rows.append((_parse_iso(payload["evaluated_at"]), payload, path))
        except SnapshotIntegrityError:
            issues.append(f"entry {index}: snapshot content hash or ledger metadata mismatch")
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            issues.append(f"entry {index}: snapshot file is unreadable or invalid")
        expected_prev = recorded_hash
    if not allow_unledgered and {path.name for path in snapshots_dir.glob("*.json")} - names:
        issues.append("unledgered snapshot files are present")
    return rows, {"ok": not issues, "length": len(entries), "issues": issues}


def verify_snapshot_chain(lake_dir: str | Path) -> dict[str, Any]:
    """Verify local snapshot content and ledger linkage; this is not external anchoring."""
    return _snapshot_chain_rows(Path(lake_dir).resolve(), metadata_only=True)[1]


def _parse_iso(value: str | datetime) -> datetime:
    """Parse an ISO date/datetime into a tz-aware UTC datetime.

    Accepts trailing ``Z``, naive values (assumed UTC), and bare dates
    (``2026-05-20`` -> start of that day). Raises ``ValueError`` on garbage so
    callers can surface a 400.
    """
    if isinstance(value, datetime):
        parsed = value
    else:
        text = value.strip()
        if not text:
            raise ValueError("timestamp must not be empty")
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _iter_snapshots(
    lake_dir: str | Path, *, limit: int | None = None, snapshot_id: str | None = None, metadata_only: bool = False
) -> list[tuple[datetime, dict[str, Any], Path]]:
    """Return verified ledger-backed payloads, without modifying corrupt history."""
    rows, result = _snapshot_chain_rows(
        Path(lake_dir).resolve(), limit=limit, snapshot_id=snapshot_id, metadata_only=metadata_only
    )
    if not result["ok"]:
        raise SnapshotIntegrityError("snapshot integrity verification failed")
    return sorted(rows, key=lambda item: item[0])


def list_snapshot_times(lake_dir: str | Path) -> list[str]:
    """Return the ``evaluated_at`` timestamps of all snapshots, oldest-first."""
    return [payload["evaluated_at"] for _ts, payload, _path in _iter_snapshots(lake_dir, metadata_only=True)]


_SNAPSHOT_ID_RE = re.compile(r"^[A-Za-z0-9._+=,@:-]+$")


def _is_safe_snapshot_token(token: str) -> bool:
    if not token or token in {".", ".."}:
        return False
    if Path(token).is_absolute():
        return False
    if "/" in token or "\\" in token:
        return False
    return bool(_SNAPSHOT_ID_RE.fullmatch(token))


def normalize_snapshot_id(snapshot_id: str) -> str | None:
    """Return a safe snapshot id token, or ``None`` when the input is unsafe."""
    token = snapshot_id.strip()
    if not _is_safe_snapshot_token(token):
        return None
    return token


def safe_snapshot_export_filename(snapshot_id: str) -> str:
    """Build a header-safe PDF attachment filename from a snapshot id."""
    token = normalize_snapshot_id(snapshot_id) or "snapshot"
    stem = re.sub(r"[^A-Za-z0-9._-]", "", token)[:80] or "snapshot"
    return f"trustops-executive-{stem}.pdf"


def _resolve_snapshot(lake_dir: str | Path, snapshot_id: str) -> tuple[dict[str, Any], Path] | None:
    token = normalize_snapshot_id(snapshot_id)
    if token is None:
        return None
    rows = _iter_snapshots(lake_dir, snapshot_id=token)
    matches = [(payload, path) for _time, payload, path in rows if path.stem == token]
    if not matches:
        matches = [
            (payload, path) for _time, payload, path in rows if str(payload["assessment_hash"]).startswith(token)
        ]
    if len(matches) > 1:
        raise ValueError("snapshot identifier is ambiguous")
    return matches[0] if matches else None


def resolve_snapshot_path(lake_dir: str | Path, snapshot_id: str) -> Path | None:
    """Resolve a verified ledger entry by filename stem or unique content hash prefix."""
    result = _resolve_snapshot(lake_dir, snapshot_id)
    return result[1] if result else None


def load_snapshot(lake_dir: str | Path, snapshot_id: str) -> dict[str, Any]:
    """Return the same payload that was verified, without an unverified second read."""
    result = _resolve_snapshot(lake_dir, snapshot_id)
    if result is None:
        raise FileNotFoundError(f"snapshot not found: {snapshot_id}")
    return result[0]


def posture_as_of(lake_dir: str | Path, *, as_of: str | datetime) -> dict[str, Any]:
    """Return the posture from the most recent snapshot at/before ``as_of``.

    Walks the immutable point-in-time snapshots in ``gold/snapshots/`` and picks
    the newest one whose ``evaluated_at`` is ``<= as_of``. The returned object
    carries the snapshot's ``posture`` summary plus the snapshot's
    ``evaluated_at`` / ``assessment_hash`` and the ``requested_as_of`` echo.

    If no snapshot exists at/before ``as_of`` (or none exist at all), returns a
    null-posture result with ``available_from`` set to the earliest snapshot's
    ``evaluated_at`` (``None`` when there are no snapshots) so the caller can
    explain why the answer is empty.

    ``as_of`` may be a ``datetime`` or an ISO date/datetime string; an invalid
    string raises ``ValueError``.
    """
    requested = _parse_iso(as_of)
    requested_iso = utc_iso(requested)
    snapshots = _iter_snapshots(lake_dir)
    available_from = snapshots[0][1].get("evaluated_at") if snapshots else None

    selected: tuple[datetime, dict[str, Any], Path] | None = None
    for entry in snapshots:
        if entry[0] <= requested:
            selected = entry
        else:
            break

    if selected is None:
        return {
            "schema_version": "trustops.assessment.v1",
            "assessment_type": "point_in_time_query",
            "requested_as_of": requested_iso,
            "found": False,
            "evaluated_at": None,
            "assessment_hash": None,
            "available_from": available_from,
            "snapshot_count": len(snapshots),
            "posture": None,
        }

    _ts, payload, path = selected
    return {
        "schema_version": "trustops.assessment.v1",
        "assessment_type": "point_in_time_query",
        "requested_as_of": requested_iso,
        "found": True,
        "evaluated_at": payload.get("evaluated_at"),
        "assessment_hash": payload.get("assessment_hash"),
        "snapshot_reason": payload.get("snapshot_reason") or "manual",
        "snapshot_path": str(path),
        "available_from": available_from,
        "snapshot_count": len(snapshots),
        "posture": payload.get("posture"),
        "frameworks": payload.get("frameworks", []),
    }


def build_violations(
    events: Iterable[dict[str, Any]] | None = None,
    *,
    events_path: str | Path | None = None,
    max_violations: int | None = None,
    asset_names: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build violation rows plus aggregate counts for audit-scale lakes.

    Pass either ``events`` (a list or a row iterator) or an ``events_path`` JSONL file.
    When ``max_violations`` is set, only the top-severity rows are returned but
    summary counts cover the full input.
    """
    if events is None and events_path is None:
        raise ValueError("events or events_path is required")
    if events is not None and events_path is not None:
        raise ValueError("pass only one of events or events_path")

    iterator = iter(events or []) if events is not None else iter_jsonl(events_path)  # type: ignore[arg-type]
    return _build_violations_capped(iterator, max_violations=max_violations, asset_names=asset_names)


def _build_violations_capped(
    events: Iterable[dict[str, Any]],
    *,
    max_violations: int | None,
    asset_names: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    total = 0
    critical = 0
    high = 0
    medium = 0
    low = 0
    retained: list[dict[str, Any]] = []
    heap: list[tuple[tuple[int, str, str], dict[str, Any]]] = []

    for event in events:
        if event["status"] not in VIOLATION_STATUSES:
            continue
        for control_id in event["control_ids"]:
            total += 1
            severity = str(event["severity"])
            if severity == "critical":
                critical += 1
            elif severity == "high":
                high += 1
            elif severity == "medium":
                medium += 1
            else:
                low += 1
            row = {
                "violation_id": f"{control_id}:{event['event_id']}",
                "control_id": control_id,
                "event_id": event["event_id"],
                "asset_id": event["asset_id"],
                "asset_owner": event["asset_owner"],
                "environment": event["environment"],
                "source": event["source"],
                "event_type": event["event_type"],
                "severity": event["severity"],
                "severity_score": event["severity_score"],
                "state": "open",
                "evidence_ref": event["evidence_ref"],
                "raw_sha256": event["raw_sha256"],
                "detected_at": event["event_time"],
            }
            if asset_names and event["asset_id"] in asset_names:
                row["asset_name"] = asset_names[event["asset_id"]]
            if max_violations is None:
                retained.append(row)
                continue
            key = (int(row["severity_score"]), row["control_id"], row["event_id"])
            if len(heap) < max_violations:
                heapq.heappush(heap, (key, row))
            elif key > heap[0][0]:
                heapq.heapreplace(heap, (key, row))

    if max_violations is not None:
        retained = [item[1] for item in heap]

    summary = {
        "total_count": total,
        "returned_count": len(retained),
        "truncated": max_violations is not None and total > len(retained),
        "max_violations": max_violations,
        "severity_counts": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },
    }
    return sorted(
        retained, key=lambda item: (-int(item["severity_score"]), item["control_id"], item["event_id"])
    ), summary


def _cap_inline_violations(
    violations: list[dict[str, Any]], summary: dict[str, Any], cap: int
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Keep the ``cap`` highest-severity rows in their original order, with the same ranking as the streaming cap."""
    keep = set(
        heapq.nlargest(
            cap,
            range(len(violations)),
            key=lambda i: (
                int(violations[i]["severity_score"]),
                violations[i]["control_id"],
                violations[i]["event_id"],
            ),
        )
    )
    retained = [row for index, row in enumerate(violations) if index in keep]
    return retained, {**summary, "returned_count": len(retained), "truncated": True, "max_violations": cap}


def _framework_scores_from_controls(
    controls: list[dict[str, Any]],
    stale_controls: set[str],
) -> list[dict[str, Any]]:
    """Use the materialized control aggregates when violation detail is capped."""
    return _framework_scores(controls, None, stale_controls)


def _framework_scores(
    controls: list[dict[str, Any]],
    violations: list[dict[str, Any]] | None,
    stale_controls: set[str],
) -> list[dict[str, Any]]:
    violations_by_control: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for violation in violations or []:
        violations_by_control[violation["control_id"]].append(violation)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for control in controls:
        grouped[control["framework"]].append(control)

    rows: list[dict[str, Any]] = []
    for framework, members in grouped.items():
        total = len(members)
        failing = [row for row in members if row["status"] == "fail"]
        stale = sum(row["control_id"] in stale_controls or row.get("status") == "stale" for row in members)
        unknown = sum(row.get("status") not in {"pass", "fail", "stale"} for row in members)
        passing = sum(row.get("status") == "pass" and row["control_id"] not in stale_controls for row in members)
        if violations is None:
            scores = [min(int(row.get("risk_score") or 0), 100) for row in failing]
            count = sum(int(row.get("open_event_count") or 0) for row in members)
            critical = sum(score >= SEVERITY_SCORE["critical"] for score in scores)
            high = sum(SEVERITY_SCORE["high"] <= score < SEVERITY_SCORE["critical"] for score in scores)
        else:
            detail = [v for row in members for v in violations_by_control.get(row["control_id"], [])]
            count = len(detail)
            critical = sum(row["severity"] == "critical" for row in detail)
            high = sum(row["severity"] == "high" for row in detail)
        # Equal credit only for explicit current passes. Severity remains a risk
        # metric; adding a failure cannot improve the assessed-scope percentage.
        score = round(100 * passing / total, 2) if total else 0.0
        rows.append(
            {
                "framework": framework,
                "score": score,
                "state": "ready" if passing == total else "attention_required",
                "not_evaluated_control_count": unknown,
                "control_count": total,
                "failing_control_count": len(failing),
                "passing_control_count": passing,
                "violation_count": count,
                "stale_control_count": stale,
                "critical_violation_count": critical,
                "high_violation_count": high,
            }
        )
    return sorted(rows, key=lambda item: (float(item["score"]), item["framework"]))


def _weighted_posture_score(frameworks: list[dict[str, Any]]) -> float:
    # Nothing evaluated scores 0, never a perfect score; the state says why.
    controls = sum(int(row["control_count"]) for row in frameworks)
    if controls <= 0:
        return 0.0
    passing = sum(int(row["passing_control_count"]) for row in frameworks)
    return round(100 * passing / controls, 2)


def _posture_state(score: float, critical_violations: bool | list[dict[str, Any]], stale_controls: set[str]) -> str:
    if critical_violations if isinstance(critical_violations, bool) else critical_violations:
        return "critical"
    if score < 100 or stale_controls:
        return "attention_required"
    return "ready"


def _assessment_hash(assessment: dict[str, Any]) -> str:
    body = {key: value for key, value in assessment.items() if key != "assessment_hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def snapshot_detail_summary(snapshot_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Build an auditor-friendly snapshot detail payload (no raw bronze evidence)."""
    posture = payload.get("posture") or {}
    violations = payload.get("violations") or []
    if not isinstance(violations, list):
        violations = []
    frameworks = payload.get("frameworks") or []
    stale_controls = payload.get("stale_controls") or []
    evidence_refs: set[str] = set()
    for row in violations:
        if isinstance(row, dict):
            ref = row.get("evidence_ref")
            if isinstance(ref, str) and ref.strip():
                evidence_refs.add(ref.strip())
    stale_count = (
        len(stale_controls) if isinstance(stale_controls, list) else int(posture.get("stale_control_count") or 0)
    )
    return {
        "snapshot_id": snapshot_id,
        "evaluated_at": payload.get("evaluated_at"),
        "reason": payload.get("snapshot_reason") or "manual",
        "assessment_hash": payload.get("assessment_hash"),
        "prev_hash": payload.get("prev_hash"),
        "posture": posture,
        "frameworks": frameworks,
        "violations": violations[:50],
        "violation_count": len(violations),
        "stale_control_count": stale_count,
        "evidence_refs": sorted(evidence_refs)[:100],
        "evidence_freshness": payload.get("evidence_freshness"),
        "mapping_review": payload.get("mapping_review"),
    }
