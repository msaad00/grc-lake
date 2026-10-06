"""Common Control Framework: safeguards as the operated object.

The control catalog is framework-first — 942 requirements, each carrying its own
``evidence_requirement``. Answering all of them means answering the same question
once per framework.

A safeguard inverts that. It is the thing an operator actually runs: one evidence
requirement, one evaluation rule, one owner. Framework requirements map *into* it,
many-to-one, and framework readiness is derived from safeguard posture rather than
computed alongside it.

The relationship is many-to-many in both directions, and deliberately so:

* one safeguard satisfies many requirements across frameworks — the point of a CCF
* one requirement may need several safeguards — SOC2 CC7.2 wants both detection
  and audit logging, so it is met only when *both* pass

That second case is why :func:`requirement_status` requires every mapped safeguard
to pass. Treating "any" as sufficient would let a passing logging safeguard report
a monitoring requirement as met.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from security_lakehouse.catalog import ROOT, load_control_catalog

DEFAULT_SAFEGUARDS = ROOT / "controls" / "safeguards.json"

SCHEMA = "trustops.safeguards.v1"
VALID_ROLES = {"primary", "equivalent"}
VALID_REVIEW_STATES = {"reviewed", "proposed"}

# Effective review state of one safeguard->requirement mapping for one tenant.
# The shipped ``review_status`` is the maintainer's call; an org decision from
# the tenant's review log (see :mod:`security_lakehouse.mapping_review`) is
# layered on top and never written back to ``controls/safeguards.json``.
REVIEW_STATE_LABELS = {
    "maintainer_reviewed": "maintainer-reviewed",
    "org_reviewed": "org-reviewed",
    "proposed": "proposed",
    "needs_changes": "needs changes",
    "rejected": "rejected",
}
# One-line meaning of each state; the console glossary (console-copy.ts) and
# the CLI help repeat these verbatim, and a test pins them together.
REVIEW_STATE_DEFINITIONS = {
    "maintainer_reviewed": "Confirmed by the catalog maintainers and shipped as reviewed.",
    "org_reviewed": "Approved by a reviewer in your organization, with a rationale.",
    "proposed": "Suggested mapping that no one has reviewed; not attestable.",
    "needs_changes": "Sent back by your organization; stays in the review queue.",
    "rejected": "Rejected by your organization; excluded from coverage.",
}
ATTESTABLE_STATES = frozenset({"maintainer_reviewed", "org_reviewed"})
PENDING_STATES = frozenset({"proposed", "needs_changes"})

# These labels describe the operated CCF safeguard families, not official
# framework names. Keep the ids stable so the CLI, API, and console can join on
# the same family even when a safeguard title changes.
DEFAULT_FAMILIES = ROOT / "controls" / "families.json"


JsonObject = dict[str, Any]


def _families_payload(path: str | Path | None = None) -> JsonObject:
    payload: JsonObject = json.loads(Path(path or DEFAULT_FAMILIES).read_text(encoding="utf-8"))
    return payload


def load_ccf_families(path: str | Path | None = None) -> dict[str, JsonObject]:
    """Return the canonical CCF control families keyed by ``family_id``."""
    return {str(row["family_id"]): row for row in _families_payload(path)["families"]}


def load_ccf_categories(path: str | Path | None = None) -> list[JsonObject]:
    """Return the CCF categories in taxonomy order.

    A category groups control families for navigation and roll-up. Each family
    names exactly one category; see :func:`validate_ccf_taxonomy`.
    """
    return list(_families_payload(path).get("categories", []))


def validate_ccf_taxonomy(payload: JsonObject) -> list[str]:
    """Return problems with the category -> family taxonomy; empty means consistent."""
    problems: list[str] = []
    category_ids: list[str] = [str(row.get("category_id") or "") for row in payload.get("categories", [])]
    seen: set[str] = set()
    for category_id in category_ids:
        if not category_id:
            problems.append("a category is missing category_id")
        elif category_id in seen:
            problems.append(f"duplicate category {category_id!r}")
        seen.add(category_id)
    used: set[str] = set()
    for family in payload.get("families", []):
        family_id = family.get("family_id")
        category = family.get("category")
        if not category:
            problems.append(f"family {family_id!r} is missing category")
        elif category not in seen:
            problems.append(f"family {family_id!r} names unknown category {category!r}")
        else:
            used.add(str(category))
    for category_id in sorted(seen - used - {""}):
        problems.append(f"category {category_id!r} has no families")
    return problems


def _validate_mapping_source(source: Any, *, context: str) -> list[str]:
    """Validate provenance for a published crosswalk mapping."""
    if not isinstance(source, dict):
        return [f"{context}: mapping_source must be an object"]

    problems: list[str] = []
    for field in ("name", "locator"):
        if not isinstance(source.get(field), str) or not source[field].strip():
            problems.append(f"{context}: mapping_source.{field} must be a non-empty string")

    url = source.get("url")
    if not isinstance(url, str) or not url.startswith("https://"):
        problems.append(f"{context}: mapping_source.url must use https")

    digest = source.get("sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        problems.append(f"{context}: mapping_source.sha256 must be 64 lowercase hexadecimal characters")
    return problems


def load_safeguards(path: str | Path | None = None) -> JsonObject:
    """Return the raw safeguards payload."""
    payload = json.loads(Path(path or DEFAULT_SAFEGUARDS).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("safeguards"), list):
        raise ValueError("safeguards file must contain a `safeguards` list")
    catalog = load_control_catalog()
    for entry in payload["safeguards"]:
        for member in entry.get("satisfies", []):
            if "control_version" in member:
                member["current_control_version"] = catalog.get(member["control_id"], {}).get("version", "1.0.0")
    return payload


def validate_safeguards(payload: JsonObject, *, catalog: dict[str, Any] | None = None) -> list[str]:
    """Return a list of problems; empty means the CCF is internally consistent.

    Returns rather than raises so a caller can report every problem at once —
    a curation pass wants the whole list, not the first failure.
    """
    problems: list[str] = []
    if payload.get("schema") != SCHEMA:
        problems.append(f"schema must be {SCHEMA!r}, got {payload.get('schema')!r}")

    known = set(catalog if catalog is not None else load_control_catalog())
    families = load_ccf_families()
    problems.extend(validate_ccf_taxonomy(_families_payload()))
    seen_ids: set[str] = set()

    for entry in payload.get("safeguards", []):
        sid = entry.get("safeguard_id")
        if not sid:
            problems.append("a safeguard is missing safeguard_id")
            continue
        if sid in seen_ids:
            problems.append(f"{sid}: duplicate safeguard_id")
        seen_ids.add(sid)
        if entry.get("risk_domain") not in families:
            problems.append(f"{sid}: unknown CCF family {entry.get('risk_domain')!r}")

        if not entry.get("asset_types"):
            problems.append(f"{sid}: missing asset_types — a safeguard must say what it applies to")

        for field in ("title", "risk_domain", "objective", "evidence_requirement", "evaluation_rule", "owner"):
            if not entry.get(field):
                problems.append(f"{sid}: missing {field}")

        if "mapping_source" in entry:
            problems.extend(_validate_mapping_source(entry["mapping_source"], context=str(sid)))

        satisfies = entry.get("satisfies")
        if not isinstance(satisfies, list) or not satisfies:
            problems.append(f"{sid}: must satisfy at least one framework requirement")
            continue

        primaries = [m for m in satisfies if m.get("role") == "primary"]
        if len(primaries) != 1:
            problems.append(f"{sid}: expected exactly one primary requirement, found {len(primaries)}")

        for member in satisfies:
            control_id = member.get("control_id")
            if control_id not in known:
                problems.append(f"{sid}: unknown control_id {control_id!r}")
            role = member.get("role", "equivalent")
            if role not in VALID_ROLES:
                problems.append(f"{sid}: invalid role {role!r} on {control_id!r}")
            review = member.get("review_status", "reviewed")
            if review not in VALID_REVIEW_STATES:
                problems.append(f"{sid}: invalid review_status {review!r} on {control_id!r}")
            if "mapping_source" in member:
                problems.extend(_validate_mapping_source(member["mapping_source"], context=f"{sid}/{control_id}"))

    return problems


def effective_review_state(member: JsonObject, decision: str | None = None) -> str:
    """Return a mapping's effective review state. Every "is it reviewed" check calls this.

    Coverage counts, the review queue, OSCAL, and the snapshot attestation all
    read it. ``decision`` is the tenant's latest org decision for the mapping
    (``approve`` / ``reject`` / ``needs_changes``) or ``None``; with ``None`` a
    member already annotated by the org overlay keeps its annotated state.

    * no org decision: shipped ``reviewed`` (the default for legacy rows) is
      ``maintainer_reviewed``; anything else is ``proposed``
    * ``approve``: ``org_reviewed`` for a proposed mapping; a maintainer-reviewed
      mapping stays ``maintainer_reviewed`` so the two are never double counted
    * ``needs_changes``: not attestable for this tenant, still evaluatable
    * ``reject``: removed from this tenant's evaluated coverage
    """
    if decision is None:
        annotated = member.get("effective_review_state")
        if isinstance(annotated, str) and annotated in REVIEW_STATE_LABELS:
            return annotated
    if decision == "reject":
        return "rejected"
    if decision == "needs_changes":
        return "needs_changes"
    version_matches = member.get("control_version") == member.get(
        "current_control_version", member.get("control_version")
    )
    if member.get("review_status", "reviewed") == "reviewed" and version_matches:
        return "maintainer_reviewed"
    if decision == "approve":
        return "org_reviewed"
    return "proposed"


def safeguards_by_requirement(
    payload: JsonObject | None = None, *, reviewed_only: bool = False
) -> dict[str, list[str]]:
    """Map each framework control_id to the safeguard ids that satisfy it.

    ``reviewed_only`` drops mappings nobody has confirmed (maintainer or org).
    Attestation should use it; discovery and curation queues should not.
    Org-rejected mappings are never returned.
    """
    data = payload or load_safeguards()
    out: dict[str, list[str]] = {}
    for entry in data["safeguards"]:
        for member in entry.get("satisfies", []):
            state = effective_review_state(member)
            if state == "rejected":
                continue
            if reviewed_only and state not in ATTESTABLE_STATES:
                continue
            out.setdefault(str(member.get("control_id")), []).append(str(entry["safeguard_id"]))
    return out


def mapping_review_queue(
    payload: JsonObject | None = None,
    *,
    framework_id: str | None = None,
    risk_domain: str | None = None,
) -> list[JsonObject]:
    """Proposed (unreviewed) safeguard→requirement mappings awaiting expert sign-off.

    Read-only curation aid — it never promotes a mapping (that equivalence call is
    the reviewer's). Each item carries the ``reviewed_anchors`` already confirmed on
    the same safeguard, so a reviewer can judge a proposed equivalence against
    mappings they already trust and accept/reject fast. Source-backed items carry
    the published crosswalk provenance and exact locator. This is the backlog
    whose review grows the *attestable* coverage number.
    """
    items: list[JsonObject] = []
    for item in mapping_review_items(payload, framework_id=framework_id, risk_domain=risk_domain):
        if item["review_state"] not in PENDING_STATES:
            continue
        if item["mapping_source"] is None:
            del item["mapping_source"]
        items.append(item)
    return items


def member_mapping_source(entry: JsonObject, member: JsonObject) -> JsonObject | None:
    """Return the published citation backing one mapping, if any.

    A member proposed by title theme has no citation of its own and must not
    inherit the safeguard's crosswalk citation, which covers other frameworks'
    members.
    """
    if "mapping_source" in member:
        source = member.get("mapping_source")
    elif member.get("mapping_basis") == "title_theme":
        source = None
    else:
        source = entry.get("mapping_source")
    return source if isinstance(source, dict) else None


def mapping_review_items(
    payload: JsonObject | None = None,
    *,
    framework_id: str | None = None,
    risk_domain: str | None = None,
) -> list[JsonObject]:
    """Every safeguard->requirement mapping with its effective review state.

    ``reviewed_anchors`` lists the other requirements on the same safeguard that
    are already confirmed, so a reviewer can judge a proposed equivalence
    against mappings they already trust.
    """
    data = payload or load_safeguards()
    items: list[JsonObject] = []
    for entry in data["safeguards"]:
        if risk_domain and str(entry.get("risk_domain")) != risk_domain:
            continue
        anchors = [
            str(member.get("control_id"))
            for member in entry.get("satisfies", [])
            if effective_review_state(member) in ATTESTABLE_STATES
        ]
        for member in entry.get("satisfies", []):
            if framework_id and str(member.get("framework_id")) != framework_id:
                continue
            control_id = str(member.get("control_id"))
            state = effective_review_state(member)
            items.append(
                {
                    "safeguard_id": str(entry["safeguard_id"]),
                    "safeguard_title": entry.get("title"),
                    "risk_domain": entry.get("risk_domain"),
                    "control_id": control_id,
                    "framework_id": str(member.get("framework_id")),
                    "role": member.get("role"),
                    "shipped_review_status": member.get("review_status", "reviewed"),
                    "review_state": state,
                    "review_label": REVIEW_STATE_LABELS[state],
                    "mapping_basis": member.get("mapping_basis"),
                    "reviewed_anchors": [anchor for anchor in anchors if anchor != control_id],
                    "mapping_source": member_mapping_source(entry, member),
                }
            )
    return items


def mapping_review_report(
    payload: JsonObject | None = None,
    *,
    framework_id: str | None = None,
    risk_domain: str | None = None,
) -> JsonObject:
    """Summarize the review backlog across frameworks and normalized domains."""
    items = mapping_review_queue(payload, framework_id=framework_id, risk_domain=risk_domain)
    sourced = [item for item in items if item.get("mapping_source")]
    unsourced = [item for item in items if not item.get("mapping_source")]

    def count_by(rows: list[JsonObject], field: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in rows:
            value = str(item[field])
            counts[value] = counts.get(value, 0) + 1
        return dict(sorted(counts.items()))

    return {
        "proposed_mapping_count": len(items),
        "source_backed_mapping_count": len(sourced),
        "unsourced_mapping_count": len(unsourced),
        "by_framework": count_by(items, "framework_id"),
        "by_risk_domain": count_by(items, "risk_domain"),
        "source_backed_by_framework": count_by(sourced, "framework_id"),
        "unsourced_by_framework": count_by(unsourced, "framework_id"),
        "items": items,
    }


def requirement_status(control_id: str, safeguard_results: dict[str, str], payload: JsonObject | None = None) -> str:
    """Derive one framework requirement's status from its safeguards.

    ``unmapped`` when no safeguard claims it — distinct from ``fail``, because
    "we have not modelled this yet" and "we tested it and it failed" are different
    answers to an auditor.
    """
    mapped = safeguards_by_requirement(payload).get(control_id, [])
    if not mapped:
        return "unmapped"
    statuses = {safeguard_results.get(sid, "unknown") for sid in mapped}
    if "fail" in statuses:
        return "fail"
    if statuses == {"pass"}:
        return "pass"
    return "unknown"


def safeguards_for_asset_type(asset_type: str, payload: JsonObject | None = None) -> list[str]:
    """Safeguards that apply to an asset type.

    The catalog already records ``asset_types`` per requirement, and evaluation
    targets resources rather than frameworks — so a safeguard has to carry the
    union of what its requirements apply to, or the operated object cannot be
    pointed at anything.
    """
    data = payload or load_safeguards()
    return sorted(
        str(entry["safeguard_id"]) for entry in data["safeguards"] if asset_type in (entry.get("asset_types") or [])
    )


def _mapping_ledger() -> dict[str, Any]:
    return {
        "safeguard_count": 0,
        "frameworks": set(),
        "control_ids": set(),
        "mapping_count": 0,
        "states": dict.fromkeys(REVIEW_STATE_LABELS, 0),
    }


def _add_safeguard(ledger: dict[str, Any], entry: JsonObject) -> None:
    ledger["safeguard_count"] += 1
    for member in entry.get("satisfies", []):
        state = effective_review_state(member)
        ledger["mapping_count"] += 1
        ledger["states"][state] += 1
        if state == "rejected":
            continue
        ledger["control_ids"].add(str(member.get("control_id")))
        framework_id = member.get("framework_id")
        if framework_id:
            ledger["frameworks"].add(str(framework_id))


def _ledger_counts(ledger: dict[str, Any]) -> JsonObject:
    states = ledger["states"]
    reviewed = int(states["maintainer_reviewed"] + states["org_reviewed"])
    proposed = int(states["proposed"] + states["needs_changes"])
    if not reviewed:
        state = "proposed_only"
    elif proposed:
        state = "partially_reviewed"
    else:
        state = "reviewed"
    return {
        "safeguard_count": ledger["safeguard_count"],
        "framework_count": len(ledger["frameworks"]),
        "frameworks": sorted(ledger["frameworks"]),
        "mapped_requirement_count": len(ledger["control_ids"]),
        "mapping_count": ledger["mapping_count"],
        # reviewed = maintainer + org; the split is reported alongside so
        # the two kinds of confirmation are never blended.
        "reviewed_mapping_count": reviewed,
        "maintainer_reviewed_mapping_count": states["maintainer_reviewed"],
        "org_reviewed_mapping_count": states["org_reviewed"],
        "proposed_mapping_count": proposed,
        "needs_changes_mapping_count": states["needs_changes"],
        "rejected_mapping_count": states["rejected"],
        "state": state,
    }


def coverage_by_family(payload: JsonObject | None = None) -> list[JsonObject]:
    """Report CCF coverage by operated safeguard family.

    A family is the safeguard's ``risk_domain``. This is deliberately separate
    from framework coverage: a family can touch several frameworks, and a
    proposed mapping makes a requirement evaluatable but not attestable. The
    ledger preserves both counts so the console can show breadth without
    overstating assurance.
    """
    data = payload or load_safeguards()
    families = load_ccf_families()
    category_labels = {str(row["category_id"]): str(row["label"]) for row in load_ccf_categories()}
    grouped: dict[str, dict[str, Any]] = {}
    for entry in data["safeguards"]:
        family_id = str(entry.get("risk_domain") or "uncategorized")
        _add_safeguard(grouped.setdefault(family_id, _mapping_ledger()), entry)

    rows: list[JsonObject] = []
    for family_id, ledger in sorted(grouped.items()):
        definition = families.get(family_id, {})
        category_id = str(definition.get("category") or "")
        rows.append(
            {
                "family_id": family_id,
                "label": definition.get("label", family_id.replace("-", " ").title()),
                "description": definition.get("description", ""),
                "category_id": category_id,
                "category_label": category_labels.get(category_id, ""),
                "nist_800_53_families": list(definition.get("nist_800_53_families", [])),
                "cis_controls": list(definition.get("cis_controls", [])),
                **_ledger_counts(ledger),
            }
        )
    return rows


def coverage_by_category(payload: JsonObject | None = None) -> list[JsonObject]:
    """Roll the family ledger up to CCF categories, in taxonomy order.

    Requirement and framework counts are distinct across the category, not a
    sum over its families, because two families can map the same requirement.
    """
    data = payload or load_safeguards()
    families = load_ccf_families()
    ledgers: dict[str, dict[str, Any]] = {}
    for entry in data["safeguards"]:
        category_id = str(families.get(str(entry.get("risk_domain")), {}).get("category") or "")
        _add_safeguard(ledgers.setdefault(category_id, _mapping_ledger()), entry)

    rows: list[JsonObject] = []
    for category in load_ccf_categories():
        category_id = str(category["category_id"])
        family_ids = [family_id for family_id, row in families.items() if row.get("category") == category_id]
        rows.append(
            {
                "category_id": category_id,
                "label": category["label"],
                "description": category.get("description", ""),
                "family_ids": family_ids,
                "family_count": len(family_ids),
                **_ledger_counts(ledgers.get(category_id, _mapping_ledger())),
            }
        )
    return rows


def coverage_by_framework(payload: JsonObject | None = None, *, catalog: dict[str, Any] | None = None) -> JsonObject:
    """Report how much of each framework the CCF currently covers.

    Requirement counts are disjoint: ``maintainer_reviewed`` requirements have at
    least one maintainer-reviewed mapping; ``org_reviewed`` requirements are
    attestable only through an org approval; ``proposed`` are evaluatable but not
    attestable. ``*_mappings`` counts are per safeguard->requirement link.
    ``rejected_requirements`` lost all evaluated coverage to org rejections.
    """
    controls = catalog if catalog is not None else load_control_catalog()
    data = payload or load_safeguards()
    mapped = safeguards_by_requirement(data)
    states_by_control: dict[str, set[str]] = {}
    mapping_states: dict[str, dict[str, int]] = {}
    for entry in data["safeguards"]:
        for member in entry.get("satisfies", []):
            control_id = str(member.get("control_id"))
            state = effective_review_state(member)
            states_by_control.setdefault(control_id, set()).add(state)
            framework = str(controls.get(control_id, {}).get("framework_id") or member.get("framework_id") or "unknown")
            counts = mapping_states.setdefault(framework, dict.fromkeys(REVIEW_STATE_LABELS, 0))
            counts[state] += 1

    def requirement_bucket(control_id: str) -> str | None:
        states = states_by_control.get(control_id, set())
        if not states:
            return None
        if "maintainer_reviewed" in states:
            return "maintainer_reviewed"
        if "org_reviewed" in states:
            return "org_reviewed"
        if states & PENDING_STATES:
            return "proposed"
        return "rejected"

    per_framework: dict[str, dict[str, int]] = {}
    buckets: dict[str, int] = dict.fromkeys(("maintainer_reviewed", "org_reviewed", "proposed", "rejected"), 0)
    for control_id, control in controls.items():
        framework = str(control.get("framework_id") or "unknown")
        row = per_framework.setdefault(
            framework,
            {"controls": 0, "covered": 0, "maintainer_reviewed": 0, "org_reviewed": 0, "rejected_requirements": 0},
        )
        row["controls"] += 1
        if control_id in mapped:
            row["covered"] += 1
        bucket = requirement_bucket(control_id)
        if bucket is not None:
            buckets[bucket] += 1
        if bucket in {"maintainer_reviewed", "org_reviewed"}:
            row[bucket] += 1
        elif bucket == "rejected":
            row["rejected_requirements"] += 1
    for framework, row in per_framework.items():
        counts = mapping_states.get(framework, dict.fromkeys(REVIEW_STATE_LABELS, 0))
        row["rejected_mappings"] = counts["rejected"]
        row["needs_changes_mappings"] = counts["needs_changes"]

    total = len(controls)
    covered = sum(1 for cid in controls if cid in mapped)
    reviewed = buckets["maintainer_reviewed"] + buckets["org_reviewed"]
    all_states = {state: sum(counts[state] for counts in mapping_states.values()) for state in REVIEW_STATE_LABELS}
    return {
        "safeguards": len(data["safeguards"]),
        "controls": total,
        "covered": covered,
        # Split so unconfirmed curation is never reported as attested coverage,
        # and org confirmation is never blended into maintainer review.
        "reviewed": reviewed,
        "maintainer_reviewed": buckets["maintainer_reviewed"],
        "org_reviewed": buckets["org_reviewed"],
        "proposed": covered - reviewed,
        "rejected_requirements": buckets["rejected"],
        "maintainer_reviewed_mappings": all_states["maintainer_reviewed"],
        "org_reviewed_mappings": all_states["org_reviewed"],
        "needs_changes_mappings": all_states["needs_changes"],
        "rejected_mappings": all_states["rejected"],
        "reviewed_pct": round(100.0 * reviewed / total, 1) if total else 0.0,
        "uncovered": total - covered,
        "coverage_pct": round(100.0 * covered / total, 1) if total else 0.0,
        "frameworks": {
            name: {
                **row,
                "coverage_pct": round(100.0 * row["covered"] / row["controls"], 1) if row["controls"] else 0.0,
            }
            for name, row in sorted(per_framework.items())
        },
        "families": coverage_by_family(data),
        "categories": coverage_by_category(data),
    }
