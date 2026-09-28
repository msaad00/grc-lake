"""Org mapping review: attributable decisions layered over the shipped CCF.

``controls/safeguards.json`` ships each safeguard->requirement mapping as
``reviewed`` (a maintainer confirmed the equivalence) or ``proposed``. A company
using TrustOps in an audit needs its own reviewers to confirm or reject those
mappings, with a trail an auditor can follow. This module is that overlay:

* decisions are appended to ``<lake>/gold/mapping_reviews.jsonl``, a hash-chained
  log (:mod:`security_lakehouse.ledger`) serialized across processes; the shipped
  file is never modified. In server mode every tenant has its own lake, so the
  log is tenant-scoped by path.
* a decision is ``approve``, ``reject`` or ``needs_changes`` with a required
  rationale, the reviewer, a timestamp and an optional evidence reference. The
  latest decision for a mapping wins; earlier ones stay in the log and each new
  one records the decision it ``supersedes``.
* :func:`effective_safeguards` returns a copy of the shipped payload annotated
  with each mapping's effective state, which every coverage function, the review
  queue, OSCAL export and the snapshot attestation read. The state itself is
  decided in one place: :func:`security_lakehouse.safeguards.effective_review_state`.
"""

from __future__ import annotations

import copy
import uuid
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.catalog import load_control_catalog, load_framework_registry
from security_lakehouse.io import read_jsonl
from security_lakehouse.ledger import append_chained_jsonl_batch, verify_chained_jsonl
from security_lakehouse.models import utc_iso
from security_lakehouse.safeguards import (
    DEFAULT_SAFEGUARDS,
    REVIEW_STATE_LABELS,
    coverage_by_framework,
    effective_review_state,
    load_ccf_families,
    load_safeguards,
    mapping_review_items,
    member_mapping_source,
)

JsonObject = dict[str, Any]
MappingKey = tuple[str, str]

DECISIONS = ("approve", "reject", "needs_changes")
MAX_RATIONALE_CHARS = 4000
MAX_EVIDENCE_REF_CHARS = 1000
MAX_REVIEWER_CHARS = 320
MAX_BATCH_ITEMS = 500

__all__ = [
    "DECISIONS",
    "DEFAULT_SAFEGUARDS",
    "MappingReviewError",
    "decision_history",
    "effective_safeguards",
    "latest_decisions",
    "list_decisions",
    "list_review_items",
    "record_decisions",
    "review_attestation",
    "review_log_path",
    "review_progress",
    "verify_review_log",
]


class MappingReviewError(ValueError):
    """A decision that cannot be recorded; nothing from its batch was written."""


def review_log_path(lake_dir: str | Path) -> Path:
    """Return the tenant's append-only decision log."""
    return Path(lake_dir) / "gold" / "mapping_reviews.jsonl"


def _index(payload: JsonObject) -> dict[MappingKey, tuple[JsonObject, JsonObject]]:
    out: dict[MappingKey, tuple[JsonObject, JsonObject]] = {}
    for entry in payload.get("safeguards", []):
        for member in entry.get("satisfies", []):
            out[(str(entry["safeguard_id"]), str(member.get("control_id")))] = (entry, member)
    return out


def _clean_text(value: Any, *, field: str, limit: int, required: bool) -> str | None:
    text = value.strip() if isinstance(value, str) else ""
    if not text:
        if required:
            raise MappingReviewError(f"{field} is required")
        return None
    if len(text) > limit:
        raise MappingReviewError(f"{field} must be at most {limit} characters")
    return text


def record_decisions(
    lake_dir: str | Path,
    *,
    items: Iterable[Mapping[str, Any]],
    decision: str,
    rationale: str,
    reviewer: str,
    reviewer_id: str | None = None,
    reviewer_role: str | None = None,
    auth_method: str = "local",
    evidence_ref: str | None = None,
    payload: JsonObject | None = None,
    now: datetime | None = None,
) -> list[JsonObject]:
    """Record one decision for one or more mappings and return the written records.

    Every item is validated before anything is written, so a batch is all or
    nothing. ``reviewer`` must come from the authenticated principal in server
    mode; the caller, not the request body, is responsible for that.
    """
    if decision not in DECISIONS:
        raise MappingReviewError(f"decision must be one of {', '.join(DECISIONS)}")
    reason = _clean_text(rationale, field="rationale", limit=MAX_RATIONALE_CHARS, required=True)
    who = _clean_text(reviewer, field="reviewer", limit=MAX_REVIEWER_CHARS, required=True)
    evidence = _clean_text(evidence_ref, field="evidence_ref", limit=MAX_EVIDENCE_REF_CHARS, required=False)

    requested = list(items)
    if not requested:
        raise MappingReviewError("a decision must name at least one mapping")
    if len(requested) > MAX_BATCH_ITEMS:
        raise MappingReviewError(f"a decision may cover at most {MAX_BATCH_ITEMS} mappings")

    shipped = payload if payload is not None else load_safeguards()
    index = _index(shipped)
    resolved: list[tuple[MappingKey, JsonObject, JsonObject]] = []
    seen: set[MappingKey] = set()
    for raw in requested:
        if not isinstance(raw, Mapping):
            raise MappingReviewError("each mapping must be an object")
        safeguard_id = str(raw.get("safeguard_id") or "").strip()
        control_id = str(raw.get("control_id") or "").strip()
        framework_id = str(raw.get("framework_id") or "").strip()
        key = (safeguard_id, control_id)
        found = index.get(key)
        if found is None:
            raise MappingReviewError(f"no shipped mapping {safeguard_id or '?'} -> {control_id or '?'}")
        entry, member = found
        shipped_framework = str(member.get("framework_id") or "")
        if framework_id != shipped_framework:
            raise MappingReviewError(
                f"framework_id {framework_id or '?'} does not match {safeguard_id} -> {control_id} "
                f"(shipped framework {shipped_framework})"
            )
        if key in seen:
            raise MappingReviewError(f"mapping {safeguard_id} -> {control_id} appears twice in one decision")
        seen.add(key)
        resolved.append((key, entry, member))

    decided_at = utc_iso(now or datetime.now(UTC))
    batch_id = uuid.uuid4().hex

    def build(rows: list[JsonObject]) -> list[JsonObject]:
        latest: dict[MappingKey, str] = {}
        for row in rows:
            latest[(str(row.get("safeguard_id")), str(row.get("control_id")))] = str(row.get("decision_id"))
        records: list[JsonObject] = []
        for key, entry, member in resolved:
            decision_id = uuid.uuid4().hex
            records.append(
                {
                    "decision_id": decision_id,
                    "batch_id": batch_id,
                    "safeguard_id": key[0],
                    "control_id": key[1],
                    "framework_id": str(member.get("framework_id")),
                    "decision": decision,
                    "rationale": reason,
                    "reviewer": who,
                    "reviewer_id": reviewer_id,
                    "reviewer_role": reviewer_role,
                    "auth_method": auth_method,
                    "evidence_ref": evidence,
                    "source_anchor": member_mapping_source(entry, member),
                    "shipped_review_status": member.get("review_status", "reviewed"),
                    "decided_at": decided_at,
                    "supersedes": latest.get(key),
                }
            )
            latest[key] = decision_id
        return records

    return append_chained_jsonl_batch(review_log_path(lake_dir), build)


def list_decisions(
    lake_dir: str | Path,
    *,
    safeguard_id: str | None = None,
    control_id: str | None = None,
    framework_id: str | None = None,
    reviewer: str | None = None,
    decision: str | None = None,
) -> list[JsonObject]:
    """Return decisions in log order (oldest first), optionally filtered."""
    wanted = {
        "safeguard_id": safeguard_id,
        "control_id": control_id,
        "framework_id": framework_id,
        "reviewer": reviewer,
        "decision": decision,
    }
    rows = read_jsonl(review_log_path(lake_dir), missing_ok=True)
    return [row for row in rows if all(value is None or row.get(field) == value for field, value in wanted.items())]


def decision_history(lake_dir: str | Path, *, safeguard_id: str, control_id: str) -> list[JsonObject]:
    """Every decision ever recorded for one mapping, oldest first."""
    return list_decisions(lake_dir, safeguard_id=safeguard_id, control_id=control_id)


def latest_decisions(lake_dir: str | Path) -> dict[MappingKey, JsonObject]:
    """The decision in force per mapping: the last one in log order."""
    latest: dict[MappingKey, JsonObject] = {}
    for row in read_jsonl(review_log_path(lake_dir), missing_ok=True):
        latest[(str(row.get("safeguard_id")), str(row.get("control_id")))] = row
    return latest


def verify_review_log(lake_dir: str | Path) -> JsonObject:
    """Verify the decision log hash chain."""
    return verify_chained_jsonl(review_log_path(lake_dir))


def _decision_summary(row: JsonObject) -> JsonObject:
    return {
        "decision_id": row.get("decision_id"),
        "decision": row.get("decision"),
        "rationale": row.get("rationale"),
        "reviewer": row.get("reviewer"),
        "reviewer_role": row.get("reviewer_role"),
        "decided_at": row.get("decided_at"),
        "evidence_ref": row.get("evidence_ref"),
    }


def effective_safeguards(lake_dir: str | Path | None = None, *, payload: JsonObject | None = None) -> JsonObject:
    """Return a copy of the shipped safeguards with each mapping's effective state.

    Each member gains ``effective_review_state`` and ``org_review`` (the decision
    in force, or ``None``). With no lake, or no decisions, the states equal the
    shipped review status. The shipped payload is never mutated.
    """
    shipped = payload if payload is not None else load_safeguards()
    decisions = latest_decisions(lake_dir) if lake_dir is not None else {}
    effective = copy.deepcopy(shipped)
    for entry in effective.get("safeguards", []):
        for member in entry.get("satisfies", []):
            row = decisions.get((str(entry["safeguard_id"]), str(member.get("control_id"))))
            member["effective_review_state"] = effective_review_state(member, str(row.get("decision")) if row else None)
            member["org_review"] = _decision_summary(row) if row else None
    return effective


def list_review_items(
    lake_dir: str | Path | None,
    *,
    payload: JsonObject | None = None,
    framework_id: str | None = None,
    risk_domain: str | None = None,
) -> list[JsonObject]:
    """Every mapping with its effective state, basis, source anchor and latest decision."""
    effective = effective_safeguards(lake_dir, payload=payload)
    org_reviews = {
        (str(entry["safeguard_id"]), str(member.get("control_id"))): member.get("org_review")
        for entry in effective.get("safeguards", [])
        for member in entry.get("satisfies", [])
    }
    counts: dict[MappingKey, int] = {}
    if lake_dir is not None:
        for row in read_jsonl(review_log_path(lake_dir), missing_ok=True):
            key = (str(row.get("safeguard_id")), str(row.get("control_id")))
            counts[key] = counts.get(key, 0) + 1
    catalog = load_control_catalog()
    items = mapping_review_items(effective, framework_id=framework_id, risk_domain=risk_domain)
    for item in items:
        key = (item["safeguard_id"], item["control_id"])
        item["control_title"] = catalog.get(item["control_id"], {}).get("title")
        item["latest_decision"] = org_reviews.get(key)
        item["decision_count"] = counts.get(key, 0)
    return items


def review_progress(lake_dir: str | Path | None, *, payload: JsonObject | None = None) -> JsonObject:
    """Per-framework mapping counts by effective state (never blended).

    ``mapped`` is every shipped mapping for the framework and equals
    ``maintainer_reviewed + org_reviewed + needs_changes + rejected + pending``.
    """
    effective = effective_safeguards(lake_dir, payload=payload)
    registry = load_framework_registry()
    rows: dict[str, JsonObject] = {}
    for entry in effective.get("safeguards", []):
        for member in entry.get("satisfies", []):
            framework_id = str(member.get("framework_id"))
            row = rows.setdefault(
                framework_id,
                {
                    "framework_id": framework_id,
                    "mapped": 0,
                    "maintainer_reviewed": 0,
                    "org_reviewed": 0,
                    "needs_changes": 0,
                    "rejected": 0,
                    "pending": 0,
                },
            )
            state = effective_review_state(member)
            row["mapped"] += 1
            row["pending" if state == "proposed" else state] += 1
    frameworks = [rows[key] for key in sorted(rows)]
    totals = {
        field: sum(int(row[field]) for row in frameworks)
        for field in ("mapped", "maintainer_reviewed", "org_reviewed", "needs_changes", "rejected", "pending")
    }
    names = {framework_id: str(registry.get(framework_id, {}).get("name") or framework_id) for framework_id in rows}
    family_labels = load_ccf_families()
    family_ids = sorted({str(entry.get("risk_domain")) for entry in effective.get("safeguards", [])})
    families = sorted(
        (
            {"family_id": family_id, "label": str(family_labels.get(family_id, {}).get("label") or family_id)}
            for family_id in family_ids
        ),
        key=lambda row: row["label"],
    )
    return {
        "frameworks": frameworks,
        "framework_names": names,
        "families": families,
        "totals": totals,
        "states": REVIEW_STATE_LABELS,
    }


def review_attestation(lake_dir: str | Path) -> JsonObject:
    """Counts and log tip pinned into an assessment snapshot.

    Recording the log tip hash lets an auditor tie a snapshot's coverage numbers
    to the exact set of org decisions that were in force when it was frozen. A
    log that cannot be read is reported, not hidden, and does not block the
    snapshot.
    """
    try:
        log = verify_review_log(lake_dir)
        coverage = coverage_by_framework(effective_safeguards(lake_dir))
    except (OSError, ValueError) as exc:
        return {"summary": None, "decision_log": {"ok": False, "error": str(exc)}}
    return {
        "summary": {
            "catalogued": coverage["controls"],
            "mapped": coverage["covered"],
            "maintainer_reviewed": coverage["maintainer_reviewed"],
            "org_reviewed": coverage["org_reviewed"],
            "proposed": coverage["proposed"],
            "rejected_requirements": coverage["rejected_requirements"],
            "maintainer_reviewed_mappings": coverage["maintainer_reviewed_mappings"],
            "org_reviewed_mappings": coverage["org_reviewed_mappings"],
            "needs_changes_mappings": coverage["needs_changes_mappings"],
            "rejected_mappings": coverage["rejected_mappings"],
        },
        "decision_log": {
            "ok": log["ok"],
            "length": log["length"],
            "tip_hash": log["tip_hash"],
            "issues": log["issues"],
        },
    }
