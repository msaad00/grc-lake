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
from collections import defaultdict
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.evidence_freshness import (
    build_evidence_freshness,
    stale_control_ids,
    summarize_source_freshness,
)
from security_lakehouse.generations import generation_identity, generation_reader
from security_lakehouse.io import append_jsonl, iter_jsonl, read_json, read_jsonl, write_json
from security_lakehouse.ledger import chain_lock
from security_lakehouse.models import SEVERITY_SCORE, utc_iso

logger = logging.getLogger(__name__)

# Called after a snapshot is written (and the chain lock released) with
# ``(snapshot_path, assessment, new_violations, newly_failing_controls)``. See
# ``write_assessment_snapshot`` for how the diff arguments are derived.
SnapshotWrittenHook = Callable[[Path, dict[str, Any], list[dict[str, Any]], list[str]], None]

VIOLATION_STATUSES = {"open", "failed", "blocked", "noncompliant"}

# Append-only ledger that chains every snapshot to its predecessor. Each line
# records (prev_hash -> assessment_hash); because assessment_hash covers
# prev_hash, mutating or dropping any historical snapshot breaks the chain.
SNAPSHOT_LEDGER = ("gold", "snapshots", "_ledger.jsonl")


@generation_reader
def build_current_posture(
    lake_dir: str | Path,
    *,
    freshness_days: int = 7,
    now: datetime | None = None,
    max_violations: int | None = None,
) -> dict[str, Any]:
    """Build the continuously refreshed compliance posture from lake artifacts.

    When ``max_violations`` is set, only the highest-severity violations are
    retained in the payload while aggregate counts still reflect the full lake.
    """
    lake = Path(lake_dir)
    evaluated_at = now or datetime.now(UTC)
    events = read_jsonl(lake / "silver" / "normalized_events.jsonl", missing_ok=True)
    controls = read_jsonl(lake / "gold" / "control_posture.jsonl", missing_ok=True)
    control_tests = read_jsonl(lake / "gold" / "control_tests.jsonl", missing_ok=True)
    assets = read_jsonl(lake / "gold" / "asset_risk.jsonl", missing_ok=True)
    asset_names = {
        str(row["asset_id"]): str(row["asset_name"]) for row in assets if row.get("asset_id") and row.get("asset_name")
    }
    violations, violation_summary = build_violations(events, max_violations=max_violations, asset_names=asset_names)
    evidence_freshness = build_evidence_freshness(
        events,
        now=evaluated_at,
        default_slo_minutes=freshness_days * 24 * 60,
    )
    stale_controls = stale_control_ids(evidence_freshness)
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
    assessment = {
        "schema_version": "trustops.assessment.v1",
        "assessment_type": "current_posture",
        "evaluated_at": utc_iso(evaluated_at),
        "freshness_days": freshness_days,
        "posture": {
            "score": posture_score,
            "state": _posture_state(posture_score, critical_for_state, stale_controls),
            "framework_count": len(framework_scores),
            "control_count": len(controls),
            "asset_count": len(assets),
            "open_violation_count": open_violation_count,
            "critical_violation_count": critical_violation_count,
            "high_violation_count": high_violation_count,
            "failed_control_test_count": len(failed_control_tests),
            "warning_control_test_count": len(warning_control_tests),
            "stale_control_count": len(stale_controls),
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
            "stale_evidence": stale_evidence[:50],
        },
    }
    generation = generation_identity(lake)
    if generation is not None:
        assessment["generation"] = generation
    assessment["assessment_hash"] = _assessment_hash(assessment)
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
    write_json(output, build_current_posture(lake, freshness_days=freshness_days, max_violations=cap))
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
        prev_hash = _chain_tip(lake)
        prior_payload = _prior_snapshot_payload(lake)
        assessment = build_current_posture(lake, freshness_days=freshness_days)
        assessment["assessment_type"] = "point_in_time_snapshot"
        assessment["snapshot_reason"] = reason
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
        if output is None:
            ts = assessment["evaluated_at"].replace(":", "").replace("-", "")
            # Suffix with the content hash so same-timestamp freezes never collide
            # and an existing immutable snapshot is never silently overwritten.
            short = assessment["assessment_hash"][:12]
            output_path = lake / "gold" / "snapshots" / f"assessment-{ts}-{short}.json"
            if output_path.exists():
                raise FileExistsError(f"snapshot already exists, refusing to overwrite: {output_path}")
        else:
            output_path = Path(output)
        write_json(output_path, assessment)
        append_jsonl(
            _ledger_path(lake),
            {
                "evaluated_at": assessment["evaluated_at"],
                "snapshot": output_path.name,
                "prev_hash": prev_hash,
                "assessment_hash": assessment["assessment_hash"],
                "snapshot_reason": reason,
                "recorded_at": utc_iso(datetime.now(UTC)),
            },
        )
        try:
            new_violations, newly_failing_controls = _diff_violations(prior_payload, assessment)
        except Exception:  # noqa: BLE001 - the diff is a defensive best-effort add-on, never allowed to break a snapshot write
            logger.exception("violations diff failed for %s; webhook finding/control events will not fire", output_path)
            new_violations, newly_failing_controls = [], []
    # Lock released above -- the hook (and any outbound webhook delivery it
    # triggers) must never hold up a concurrent writer.
    if on_snapshot_written is not None:
        try:
            on_snapshot_written(output_path, assessment, new_violations, newly_failing_controls)
        except Exception:  # noqa: BLE001 - a hook failure must never fail a successful snapshot write
            logger.exception("on_snapshot_written hook failed for %s", output_path)
    return output_path


def verify_snapshot_chain(lake_dir: str | Path) -> dict[str, Any]:
    """Verify the snapshot hash-chain against the append-only ledger.

    Walks the ledger oldest-first and, for each entry, confirms the referenced
    snapshot file exists, recomputes its ``assessment_hash`` from content, and
    checks that the recorded hash, the file's stored hash, and the ``prev_hash``
    linkage all agree. Returns ``{"ok", "length", "issues"}`` — ``ok`` is True
    only when the chain is intact and unbroken.
    """
    lake = Path(lake_dir)
    entries = read_jsonl(_ledger_path(lake), missing_ok=True)
    snapshots_dir = lake / "gold" / "snapshots"
    issues: list[str] = []
    expected_prev: str | None = None
    for index, entry in enumerate(entries):
        name = entry.get("snapshot")
        recorded_hash = entry.get("assessment_hash")
        if entry.get("prev_hash") != expected_prev:
            issues.append(f"entry {index} ({name}): prev_hash breaks the chain")
        path = snapshots_dir / name if isinstance(name, str) else None
        if path is None or not path.exists():
            issues.append(f"entry {index} ({name}): snapshot file is missing")
            expected_prev = recorded_hash
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            issues.append(f"entry {index} ({name}): snapshot file is unreadable")
            expected_prev = recorded_hash
            continue
        recomputed = _assessment_hash(payload)
        if recomputed != recorded_hash or payload.get("assessment_hash") != recorded_hash:
            issues.append(f"entry {index} ({name}): content hash does not match the ledger")
        expected_prev = recorded_hash
    return {"ok": not issues, "length": len(entries), "issues": issues}


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


def _iter_snapshots(lake_dir: str | Path) -> list[tuple[datetime, dict[str, Any], Path]]:
    """Load assessment snapshots as ``(evaluated_at, payload, path)`` tuples.

    Snapshots with a missing/unparseable ``evaluated_at`` are skipped. The
    result is sorted oldest-first by ``evaluated_at``.
    """
    snapshots_dir = Path(lake_dir) / "gold" / "snapshots"
    if not snapshots_dir.is_dir():
        return []
    rows: list[tuple[datetime, dict[str, Any], Path]] = []
    for path in snapshots_dir.glob("assessment-*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        raw = payload.get("evaluated_at")
        if not isinstance(raw, str):
            continue
        try:
            evaluated_at = _parse_iso(raw)
        except ValueError:
            continue
        rows.append((evaluated_at, payload, path))
    return sorted(rows, key=lambda item: item[0])


def list_snapshot_times(lake_dir: str | Path) -> list[str]:
    """Return the ``evaluated_at`` timestamps of all snapshots, oldest-first."""
    return [payload["evaluated_at"] for _ts, payload, _path in _iter_snapshots(lake_dir)]


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


def resolve_snapshot_path(lake_dir: str | Path, snapshot_id: str) -> Path | None:
    """Resolve a snapshot file by filename stem or ``assessment_hash`` prefix."""
    snapshots_dir = Path(lake_dir) / "gold" / "snapshots"
    if not snapshots_dir.is_dir():
        return None
    token = normalize_snapshot_id(snapshot_id)
    if token is None:
        return None
    resolved_dir = snapshots_dir.resolve()
    for path in snapshots_dir.glob("assessment-*.json"):
        try:
            path.resolve().relative_to(resolved_dir)
        except ValueError:
            continue
        if path.stem == token:
            return path
    for path in snapshots_dir.glob("assessment-*.json"):
        try:
            path.resolve().relative_to(resolved_dir)
        except ValueError:
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        digest = payload.get("assessment_hash")
        if isinstance(digest, str) and (digest == token or digest.startswith(token)):
            return path
    return None


def load_snapshot(lake_dir: str | Path, snapshot_id: str) -> dict[str, Any]:
    """Load a point-in-time snapshot payload by id."""
    path = resolve_snapshot_path(lake_dir, snapshot_id)
    if path is None:
        raise FileNotFoundError(f"snapshot not found: {snapshot_id}")
    return json.loads(path.read_text(encoding="utf-8"))


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
    events: list[dict[str, Any]] | None = None,
    *,
    events_path: str | Path | None = None,
    max_violations: int | None = None,
    asset_names: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build violation rows plus aggregate counts for audit-scale lakes.

    Pass either an in-memory ``events`` list or an ``events_path`` JSONL file.
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


def _framework_scores_from_controls(
    controls: list[dict[str, Any]],
    stale_controls: set[str],
) -> list[dict[str, Any]]:
    """Framework rollups from gold control posture rows (audit-scale safe)."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for control in controls:
        grouped[control["framework"]].append(control)

    rows: list[dict[str, Any]] = []
    for framework, framework_controls in grouped.items():
        total = len(framework_controls)
        failing = [control for control in framework_controls if control["status"] == "fail"]
        stale = [control for control in framework_controls if control["control_id"] in stale_controls]
        open_events = sum(int(control.get("open_event_count") or 0) for control in framework_controls)
        risk_penalty = sum(min(int(control.get("risk_score") or 0), 100) for control in failing)
        max_penalty = max(1, total * 100)
        score = max(0, round(100 - ((risk_penalty / max_penalty) * 100) - (len(stale) * 5), 2))
        rows.append(
            {
                "framework": framework,
                "score": score,
                "state": "ready" if not failing and not stale else "attention_required",
                "control_count": total,
                "failing_control_count": len(failing),
                "violation_count": open_events,
                "stale_control_count": len(stale),
                "critical_violation_count": sum(
                    1 for control in failing if int(control.get("risk_score") or 0) >= SEVERITY_SCORE["critical"]
                ),
                "high_violation_count": sum(
                    1
                    for control in failing
                    if SEVERITY_SCORE["high"] <= int(control.get("risk_score") or 0) < SEVERITY_SCORE["critical"]
                ),
            }
        )
    return sorted(rows, key=lambda item: (float(item["score"]), item["framework"]))


def _framework_scores(
    controls: list[dict[str, Any]],
    violations: list[dict[str, Any]],
    stale_controls: set[str],
) -> list[dict[str, Any]]:
    violations_by_control: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for violation in violations:
        violations_by_control[violation["control_id"]].append(violation)

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for control in controls:
        grouped[control["framework"]].append(control)

    rows: list[dict[str, Any]] = []
    for framework, framework_controls in grouped.items():
        total = len(framework_controls)
        failing = [control for control in framework_controls if control["status"] == "fail"]
        stale = [control for control in framework_controls if control["control_id"] in stale_controls]
        framework_violations = [
            v for control in framework_controls for v in violations_by_control.get(control["control_id"], [])
        ]
        risk_penalty = sum(min(int(v["severity_score"]), 100) for v in framework_violations)
        max_penalty = max(1, total * 100)
        score = max(0, round(100 - ((risk_penalty / max_penalty) * 100) - (len(stale) * 5), 2))
        rows.append(
            {
                "framework": framework,
                "score": score,
                "state": "ready" if not failing and not stale else "attention_required",
                "control_count": total,
                "failing_control_count": len(failing),
                "violation_count": len(framework_violations),
                "stale_control_count": len(stale),
                "critical_violation_count": sum(1 for v in framework_violations if v["severity"] == "critical"),
                "high_violation_count": sum(1 for v in framework_violations if v["severity"] == "high"),
            }
        )
    return sorted(rows, key=lambda item: (float(item["score"]), item["framework"]))


def _weighted_posture_score(frameworks: list[dict[str, Any]]) -> float:
    if not frameworks:
        return 100.0
    controls = sum(int(row["control_count"]) for row in frameworks)
    if controls <= 0:
        return 100.0
    total = sum(float(row["score"]) * int(row["control_count"]) for row in frameworks)
    return round(total / controls, 2)


def _posture_state(score: float, critical_violations: bool | list[dict[str, Any]], stale_controls: set[str]) -> str:
    if critical_violations if isinstance(critical_violations, bool) else critical_violations:
        return "critical"
    if score < 75 or stale_controls:
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
