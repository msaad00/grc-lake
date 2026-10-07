"""Framework coverage ledger.

Coverage is intentionally computed from the registry, control catalog, and
reviewed source mappings instead of hand-written README numbers. The ledger is
about seeded-control coverage, not a claim that TrustOps fully implements a
licensed or certification framework.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from security_lakehouse.catalog import (
    DEFAULT_CONTROL_CATALOG,
    DEFAULT_FRAMEWORK_REGISTRY,
    load_control_catalog,
    load_framework_registry,
)
from security_lakehouse.framework_provenance import build_framework_view, framework_pack_counts, framework_pack_state
from security_lakehouse.mappings import DEFAULT_MAPPINGS, article_mapping_reviewed, load_control_article_mappings
from security_lakehouse.safeguards import (
    framework_mapping_coverage,
    load_safeguards,
)

JsonObject = dict[str, Any]


def _source_policy(framework: JsonObject) -> str:
    guardrail = str(framework.get("copyright_guardrail") or "").lower()
    if "public domain" in guardrail or "public nist guidance" in guardrail:
        return "public-source citation"
    return "source-linked identifier only"


def build_framework_coverage(
    registry_path: str | Path | None = None,
    controls_path: str | Path | None = None,
    mappings_path: str | Path | None = None,
    *,
    lake_dir: str | Path | None = None,
) -> list[JsonObject]:
    """Return one coverage row per framework.

    ``mapping_coverage_pct`` means "reviewed source mappings for the seeded
    controls in this repo." It does not mean full standard coverage.

    With ``lake_dir``, the tenant's org review decisions are layered over the
    shipped safeguard mappings (see :mod:`security_lakehouse.mapping_review`):
    attestable coverage is split into maintainer-reviewed and org-reviewed
    requirements, and org-rejected mappings leave evaluated coverage.
    """
    registry = load_framework_registry(registry_path or DEFAULT_FRAMEWORK_REGISTRY)
    controls = load_control_catalog(controls_path or DEFAULT_CONTROL_CATALOG)
    mappings = load_control_article_mappings(mappings_path or DEFAULT_MAPPINGS)
    provenance = {
        str(row.get("framework_id") or ""): row
        for row in build_framework_view(
            registry_path=registry_path or DEFAULT_FRAMEWORK_REGISTRY,
            controls_path=controls_path or DEFAULT_CONTROL_CATALOG,
        )
    }

    controls_by_framework: dict[str, list[JsonObject]] = defaultdict(list)
    mappings_by_framework: dict[str, list[JsonObject]] = defaultdict(list)
    for control in controls.values():
        controls_by_framework[str(control.get("framework_id") or "")].append(control)
    for control_id, mapping in mappings.items():
        framework_id = str(mapping.get("framework_id") or "")
        if control_id in controls and framework_id:
            mappings_by_framework[framework_id].append(mapping)

    # Attestable coverage: requirements backed by a *reviewed* safeguard mapping
    # (what attestation reads via reviewed_only=True), vs merely evaluatable
    # (touched by any safeguard, reviewed or proposed). Bucketed by the same
    # control catalog so the counts are relative to seeded requirements. This is
    # the honest number — distinct from source-citation coverage above, which is
    # always 100% because every seeded control carries an official source link.
    if lake_dir is not None:
        from security_lakehouse.mapping_review import effective_safeguards

        safeguards = effective_safeguards(lake_dir)
    else:
        safeguards = load_safeguards()
    coverage = framework_mapping_coverage(safeguards, catalog=controls)
    review_log_verified = coverage["review_log_verified"]

    rows: list[JsonObject] = []
    for framework_id, framework in registry.items():
        seeded_controls = controls_by_framework.get(framework_id, [])
        mapped = mappings_by_framework.get(framework_id, [])
        seeded_count = len(seeded_controls)
        mapped_count = len(mapped)
        reviewed_count = sum(1 for mapping in mapped if article_mapping_reviewed(mapping))
        missing = sorted(
            str(control.get("control_id") or "")
            for control in seeded_controls
            if str(control.get("control_id") or "") not in mappings
        )
        source = provenance.get(framework_id, {})
        shared = coverage["frameworks"].get(framework_id, {})
        rows.append(
            {
                "framework_id": framework_id,
                "name": framework["name"],
                "version": framework["version"],
                "official_source_name": framework["official_source_name"],
                "official_source_url": framework["official_source_url"],
                "effective_date": framework.get("effective_date"),
                "superseded_by": framework.get("superseded_by"),
                "pack_state": framework_pack_state(framework, seeded_count),
                "source_sha256": framework.get("source_sha256"),
                "pulled_at": framework.get("pulled_at"),
                "freshness_state": source.get("freshness_state", "never_pulled"),
                "seeded_control_count": seeded_count,
                "source_cited_mapping_count": mapped_count,
                "reviewed_mapping_count": reviewed_count,
                "missing_mapping_count": len(missing),
                "missing_mapping_control_ids": missing,
                "seeded_mapping_coverage_pct": round(mapped_count / seeded_count * 100, 1) if seeded_count else 0.0,
                # Attestable coverage: the auditor-defensible number.
                "evaluatable_requirement_count": shared.get("covered", 0),
                "attestable_requirement_count": shared.get("reviewed", 0),
                "maintainer_reviewed_requirement_count": shared.get("maintainer_reviewed", 0),
                "org_reviewed_requirement_count": shared.get("org_reviewed", 0),
                "org_reviewed_mapping_count": shared.get("org_reviewed_mappings", 0),
                "needs_changes_mapping_count": shared.get("needs_changes_mappings", 0),
                "rejected_mapping_count": shared.get("rejected_mappings", 0),
                # False when the org decision log failed verification; the org
                # counts above then fall back to the shipped review states.
                "review_log_verified": review_log_verified,
                "contextual_mapping_count": shared.get("contextual_mappings", 0),
                "evaluatable_coverage_pct": shared.get("coverage_pct", 0.0),
                "attestable_coverage_pct": shared.get("reviewed_pct", 0.0),
                "implementation_status": framework.get("implementation_status"),
                "source_policy": _source_policy(framework),
                "asset_policy": "neutral label; no official logo or certification seal bundled",
            }
        )
    return sorted(rows, key=lambda row: str(row["framework_id"]))


def framework_coverage_summary(
    rows: list[JsonObject],
    applicability_rows: list[JsonObject] | None = None,
) -> JsonObject:
    seeded = sum(int(row["seeded_control_count"]) for row in rows)
    mapped = sum(int(row["source_cited_mapping_count"]) for row in rows)
    reviewed = sum(int(row["reviewed_mapping_count"]) for row in rows)
    missing = sum(int(row["missing_mapping_count"]) for row in rows)
    evaluatable = sum(int(row.get("evaluatable_requirement_count", 0)) for row in rows)
    attestable = sum(int(row.get("attestable_requirement_count", 0)) for row in rows)
    maintainer_reviewed = sum(int(row.get("maintainer_reviewed_requirement_count", 0)) for row in rows)
    org_reviewed = sum(int(row.get("org_reviewed_requirement_count", 0)) for row in rows)
    applicability = applicability_rows if applicability_rows is not None else build_control_asset_applicability()
    implemented = [row for row in rows if str(row.get("implementation_status", "")).startswith("implemented")]
    planned = [row for row in rows if str(row.get("implementation_status", "")) == "planned"]
    pack_counts = framework_pack_counts(
        str(row.get("pack_state") or framework_pack_state(row, int(row["seeded_control_count"]))) for row in rows
    )
    return {
        "framework_count": len(rows),
        "implemented_framework_count": len(implemented),
        "planned_framework_count": len(planned),
        "seeded_framework_count": pack_counts["seeded_framework_count"],
        "stub_framework_count": pack_counts["stub_framework_count"],
        "superseded_framework_count": pack_counts["superseded_framework_count"],
        "seeded_control_count": seeded,
        "source_cited_mapping_count": mapped,
        "reviewed_mapping_count": reviewed,
        "missing_mapping_count": missing,
        "seeded_mapping_coverage_pct": round(mapped / seeded * 100, 1) if seeded else 0.0,
        "evaluatable_requirement_count": evaluatable,
        "attestable_requirement_count": attestable,
        "maintainer_reviewed_requirement_count": maintainer_reviewed,
        "org_reviewed_requirement_count": org_reviewed,
        "org_reviewed_mapping_count": sum(int(row.get("org_reviewed_mapping_count", 0)) for row in rows),
        "needs_changes_mapping_count": sum(int(row.get("needs_changes_mapping_count", 0)) for row in rows),
        "rejected_mapping_count": sum(int(row.get("rejected_mapping_count", 0)) for row in rows),
        "review_log_verified": all(bool(row.get("review_log_verified", True)) for row in rows),
        "contextual_mapping_count": sum(int(row.get("contextual_mapping_count", 0)) for row in rows),
        "evaluatable_coverage_pct": round(evaluatable / seeded * 100, 1) if seeded else 0.0,
        "attestable_coverage_pct": round(attestable / seeded * 100, 1) if seeded else 0.0,
        "asset_type_count": len(applicability),
        "control_asset_applicability_link_count": sum(int(row["applicable_control_count"]) for row in applicability),
        "official_logo_count": 0,
        "certification_seal_count": 0,
    }


def build_control_asset_applicability(
    controls_path: str | Path | None = None,
) -> list[JsonObject]:
    """Return seeded control applicability counts by asset type."""
    controls = load_control_catalog(controls_path or DEFAULT_CONTROL_CATALOG)
    counts: Counter[str] = Counter()
    for control in controls.values():
        for asset_type in control.get("asset_types") or []:
            counts[str(asset_type)] += 1
    return [
        {"asset_type": asset_type, "applicable_control_count": count}
        for asset_type, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def _markdown_text(value: object) -> str:
    return str(value).replace("|", "\\|").replace("—", "-").replace("–", "-").replace("≥", ">=")


def render_framework_coverage_doc() -> str:
    """Full committed matrix doc (`docs/FRAMEWORK_COVERAGE.md`).

    Generated from the catalog + CCF safeguards; the committed file is gated
    against this so it can never drift. Regenerate with ``make coverage-doc``.
    """
    body = render_framework_coverage_markdown(build_framework_coverage())
    return (
        "# Framework Coverage Matrix\n\n"
        "Generated from the control catalog + CCF safeguards — never hand-edited.\n"
        "Regenerate with `make coverage-doc`. Mapping coverage measures catalog curation,\n"
        "not operating effectiveness, assessment completion, or certification. API fields\n"
        "retain `evaluatable` and `attestable` names for compatibility.\n\n" + body + "\n"
    )


def render_framework_coverage_markdown(
    rows: list[JsonObject],
    applicability_rows: list[JsonObject] | None = None,
) -> str:
    applicability = applicability_rows if applicability_rows is not None else build_control_asset_applicability()
    summary = framework_coverage_summary(rows, applicability)
    lines = [
        "| Framework | Official source | Status | Requirements | Source-cited | Mapped | Reviewed mappings | Reviewed % | Source state |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in rows:
        lines.append(
            "| {name} | [{source}]({url}) | {status} | {controls} | {mappings} | {evaluatable} | {attestable} | {attestable_pct}% | {freshness} |".format(
                name=_markdown_text(row["name"]),
                source=_markdown_text(row["official_source_name"]),
                url=_markdown_text(row["official_source_url"]),
                status=_markdown_text(row.get("implementation_status") or "unknown"),
                controls=row["seeded_control_count"],
                mappings=row["source_cited_mapping_count"],
                evaluatable=row.get("evaluatable_requirement_count", 0),
                attestable=row.get("attestable_requirement_count", 0),
                attestable_pct=row.get("attestable_coverage_pct", 0.0),
                freshness=str(row["freshness_state"]).replace("_", " "),
            )
        )
    applicability_lines = [
        "| Asset type | Applicable controls |",
        "| --- | ---: |",
    ]
    for row in applicability:
        applicability_lines.append(f"| `{_markdown_text(row['asset_type'])}` | {row['applicable_control_count']} |")
    return "\n".join(
        [
            f"Framework packs: {summary['seeded_framework_count']} with catalogued requirements"
            f" ({summary['stub_framework_count']} more registry entries planned or superseded)",
            f"Requirements catalogued: {summary['seeded_control_count']} (all source-cited)",
            f"Mapped (touched by a safeguard): {summary['evaluatable_requirement_count']} "
            f"({summary['evaluatable_coverage_pct']}%)",
            f"**Reviewed safeguard mappings: "
            f"{summary['attestable_requirement_count']} ({summary['attestable_coverage_pct']}%)**",
            f"Asset types modeled: {summary['asset_type_count']}",
            "",
            "> `Source-cited` = the requirement has an official source link. "
            + "`Mapped` = a safeguard claims it (reviewed or proposed). "
            + "`Reviewed` = a human has confirmed the safeguard-to-requirement mapping. "
            + "An assessment still needs scoped evidence and tests of operating effectiveness.",
            "",
            *lines,
            "",
            "## Control-To-Asset Applicability",
            "",
            "Every seeded control declares the asset types it applies to. The pipeline joins those declarations into gold asset rows as `applicable_control_ids`.",
            "",
            *applicability_lines,
        ]
    )
