"""Full framework packs: SOC 2, NIST AI RMF, FedRAMP, CIS AWS, and ISO catalogs.

Packs define every official criterion/subcategory ID with short internal titles
(no licensed normative text). ``sync_framework_packs`` merges pack rows into the
active control catalog and reviewed mappings without removing other frameworks
or richer hand-authored control definitions.

Each ``*_specs()`` function is manifest-driven: identifiers, titles, and the
source citation live as data in a JSON manifest under
``frameworks/packs/data/``, read via
:func:`security_lakehouse.pack_manifest.pack_from_manifest`. Each function is
a thin wrapper around that manifest plus a small, named, per-framework
transform (ID normalization, risk-domain/owner lookups, evidence-requirement
wording) — see ``docs/FRAMEWORK_PACKS.md`` for the schema and the "add a new
framework" workflow.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from security_lakehouse.catalog import DEFAULT_CONTROL_CATALOG, ROOT
from security_lakehouse.catalog_versions import (
    DEFAULT_BUNDLE_LOCK_PATH,
    write_bundle_lock,
)
from security_lakehouse.jsontypes import JsonObject
from security_lakehouse.mappings import DEFAULT_MAPPINGS
from security_lakehouse.pack_data import (
    CIS_AWS_SOURCE,
    CMMC_2_LEVEL2_SOURCE,
    FEDRAMP_SOURCE,
    ISO_27001_SOURCE,
    ISO_27017_SOURCE,
    ISO_42001_SOURCE,
    NIST_CSF_2_COUNT,
    NIST_CSF_2_SOURCE,
    PACK_DATA_DIR,
    cis_section_risk_domain,
    cmmc_800_171_family_risk_domain,
    csf_category_risk_domain,
    iso_27001_theme_risk_domain,
    iso_27017_risk_domain,
    nist_csf_2_outcomes,
    nist_family_risk_domain,
)
from security_lakehouse.pack_manifest import PackManifestRow, pack_from_manifest
from security_lakehouse.pack_spec import PackControlSpec

DEFAULT_VERIFIED_ARTICLE_IDS = ROOT / "frameworks" / "verified_article_ids.json"

PACK_SCOPE = "framework_packs_full_soc2_nist_fedramp_cis_iso_plus_seed"

REVIEWED_BY = "internal-trust-team"
REVIEWED_DATE = "2026-06-30"
# Packs whose identifier mappings are generated from a pinned official source
# and have not been human-reviewed; rows stay ``proposed`` until promoted.
PROPOSED_SOURCE_FRAMEWORKS = frozenset({"nist-csf-2.0", "nist-800-53-rev5", "nist-rmf-800-37r2"})
NIST_800_53_SOURCE = "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"
NIST_800_171_R3_SOURCE = "https://csrc.nist.gov/pubs/sp/800/171/r3/final"
SOURCE_RECONCILED_BY = "automated-source-reconciliation"
# Packs whose catalog rows are generated from a pinned official source and
# carry that provenance honestly: proposed, attributed to source
# reconciliation, dated by the source pull. Value is the manifest pulled_at.
SOURCE_RECONCILED_PACKS = {
    framework_id: str(json.loads((PACK_DATA_DIR / manifest).read_text(encoding="utf-8"))["source"]["pulled_at"])
    for framework_id, manifest in {
        "nist-800-171-rev3": "nist_800_171_rev3.json",
        "nis2-2022-2555": "nis2_2022_2555.json",
        "dora-2022-2554": "dora_2022_2554.json",
    }.items()
}
NIST_RMF_SOURCE = "https://csrc.nist.gov/pubs/sp/800/37/r2/final"
RMF_STEP_RISK_DOMAIN = {
    "P": "governance",
    "C": "risk-management",
    "S": "governance",
    "I": "controls-operations",
    "A": "risk-management",
    "R": "risk-management",
    "M": "monitoring",
}

SOC2_SOURCE = (
    "https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022"
)
NIST_AI_RMF_SOURCE = "https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10"
NIST_CSF_2_SUBCATEGORY_COUNT = NIST_CSF_2_COUNT

# Expected full pack sizes (used by tests and coverage gates).
SOC2_COMMON_CRITERIA_COUNT = 33
SOC2_TSC_EXTENSION_COUNT = 28
SOC2_FULL_PACK_COUNT = SOC2_COMMON_CRITERIA_COUNT + SOC2_TSC_EXTENSION_COUNT
NIST_AI_RMF_SUBCATEGORY_COUNT = 72


def _soc2_risk_domain(cc: str) -> str:
    series = cc.split(".")[0]
    if series.startswith("A"):
        return "availability"
    if series.startswith("C"):
        return "confidentiality"
    if series.startswith("PI"):
        return "processing-integrity"
    if series.startswith("P") and not series.startswith("PI"):
        return "privacy"
    return {
        "CC1": "governance",
        "CC2": "governance",
        "CC3": "risk-management",
        "CC4": "risk-management",
        "CC5": "controls-operations",
        "CC6": "identity",
        "CC7": "monitoring",
        "CC8": "change-management",
        "CC9": "vendor-risk",
    }.get(series, "governance")


def _soc2_owner(risk_domain: str) -> str:
    return {
        "governance": "grc",
        "risk-management": "grc",
        "controls-operations": "security-platform",
        "identity": "security-platform",
        "monitoring": "detection-engineering",
        "change-management": "platform-engineering",
        "vendor-risk": "grc",
        "availability": "platform-engineering",
        "confidentiality": "security-platform",
        "processing-integrity": "platform-engineering",
        "privacy": "grc",
    }.get(risk_domain, "security-platform")


def _soc2_assets(risk_domain: str) -> tuple[str, ...]:
    mapping: dict[str, tuple[str, ...]] = {
        "governance": ("service", "audit_log"),
        "risk-management": ("service", "audit_log"),
        "controls-operations": ("cloud_policy", "cloud_resource", "service"),
        "identity": ("iam_role", "identity_user", "identity_group", "okta_user"),
        "monitoring": ("audit_log", "service", "host"),
        "change-management": ("repo", "service", "container_image"),
        "vendor-risk": ("service", "data_store"),
        "availability": ("service", "host", "data_store", "cloud_resource"),
        "confidentiality": ("data_store", "s3_bucket", "cloud_resource", "service"),
        "processing-integrity": ("service", "audit_log", "data_store"),
        "privacy": ("data_store", "service", "identity_user", "audit_log"),
    }
    return mapping.get(risk_domain, ("service",))


def _soc2_evaluation_rule(risk_domain: str) -> str:
    if risk_domain in {
        "identity",
        "monitoring",
        "controls-operations",
        "availability",
        "confidentiality",
        "processing-integrity",
    }:
        return "fail_when_open_violation_or_stale_evidence"
    if risk_domain in {"vendor-risk", "privacy"}:
        return "fail_when_high_severity_open"
    return "fail_when_missing_evidence"


def _soc2_row_transform(row: PackManifestRow) -> PackControlSpec:
    article_id, title = row.id, row.title
    risk = _soc2_risk_domain(article_id)
    owner = _soc2_owner(risk)
    return PackControlSpec(
        control_id=f"SOC2-{article_id}",
        framework_id="soc2",
        framework="SOC 2",
        framework_ref=f"SOC 2 {article_id}",
        article_id=article_id,
        title=title,
        risk_domain=risk,
        owner=owner,
        evaluation_rule=_soc2_evaluation_rule(risk),
        evidence_requirement=(
            f"Current evidence demonstrates {title.lower()} with no open high-risk failure or stale proof."
        ),
        asset_types=_soc2_assets(risk),
        source_url=SOC2_SOURCE,
        official_source_ref="soc2",
    )


def soc2_common_criteria_specs() -> list[PackControlSpec]:
    """All 33 SOC 2 Trust Services Criteria common criteria (CC1-CC9).

    Manifest-driven: identifiers and short internal titles (not AICPA
    licensed criterion text) come from ``soc2.json``'s ``common_criteria``
    rows; risk-domain/owner lookups and evidence wording stay in
    :func:`_soc2_row_transform`.
    """
    return pack_from_manifest(PACK_DATA_DIR / "soc2.json", rows_key="common_criteria", transform=_soc2_row_transform)


def soc2_tsc_extension_specs() -> list[PackControlSpec]:
    """SOC 2 supplemental TSC: Availability, Confidentiality, Processing Integrity, Privacy.

    Manifest-driven: see :func:`soc2_common_criteria_specs`; reads
    ``soc2.json``'s ``tsc_extension`` rows instead.
    """
    return pack_from_manifest(PACK_DATA_DIR / "soc2.json", rows_key="tsc_extension", transform=_soc2_row_transform)


def soc2_full_pack_specs() -> list[PackControlSpec]:
    """All 61 SOC 2 criteria: 33 common criteria plus 28 supplemental TSC extensions."""
    return soc2_common_criteria_specs() + soc2_tsc_extension_specs()


def _nist_risk_domain(func: str) -> str:
    return {
        "GOVERN": "ai-governance",
        "MAP": "ai-governance",
        "MEASURE": "ai-risk",
        "MANAGE": "ai-risk",
    }.get(func, "ai-governance")


def _nist_ai_rmf_row_transform(row: PackManifestRow) -> PackControlSpec:
    """``row.id`` is the hyphenated ref, e.g. ``GOVERN-1.1``; ``row.title`` is the
    first sentence of the official subcategory statement (NIST AI 100-1)."""
    ref = row.id
    func, category_sub = ref.split("-", 1)
    risk = _nist_risk_domain(func)
    title = f"{func} {category_sub} — {row.title}"
    return PackControlSpec(
        control_id=f"NIST-AI-RMF-{ref}",
        framework_id="nist-ai-rmf",
        framework="NIST AI RMF",
        framework_ref=f"NIST AI RMF {ref}",
        article_id=ref,
        title=title,
        risk_domain=risk,
        owner="ai-security",
        evaluation_rule="fail_when_open_violation_or_stale_evidence"
        if risk == "ai-risk"
        else "fail_when_missing_evidence",
        evidence_requirement=(f"Current AI governance evidence supports {ref} with reviewed mappings and fresh proof."),
        asset_types=("ai_model", "ai_agent", "service", "data_store"),
        source_url=NIST_AI_RMF_SOURCE,
        official_source_ref="nist-ai-rmf",
    )


def nist_ai_rmf_specs() -> list[PackControlSpec]:
    """All 72 NIST AI RMF 1.0 subcategories across GOVERN, MAP, MEASURE, MANAGE.

    Manifest-driven: identifiers come from ``nist_ai_rmf.json`` (``rows``,
    plain ``{"id": ...}`` entries — no distinct per-ID title text exists at
    this level); function-block risk-domain lookup and title/evidence
    wording stay in :func:`_nist_ai_rmf_row_transform`.
    """
    return pack_from_manifest(PACK_DATA_DIR / "nist_ai_rmf.json", transform=_nist_ai_rmf_row_transform)


def nist_csf_2_specs() -> list[PackControlSpec]:
    """Use pinned official IDs: CSF subcategory numbers are not consecutive."""
    specs: list[PackControlSpec] = []
    for article_id, title in nist_csf_2_outcomes().items():
        function, category = article_id.split("-")[0].split(".")
        risk = csf_category_risk_domain(function, category)
        specs.append(
            PackControlSpec(
                control_id=f"NIST-CSF-{article_id}",
                framework_id="nist-csf-2.0",
                framework="NIST CSF 2.0",
                framework_ref=f"NIST CSF 2.0 {article_id}",
                article_id=article_id,
                title=title,
                risk_domain=risk,
                owner=_soc2_owner(risk),
                evaluation_rule="fail_when_missing_evidence",
                evidence_requirement=f"Evidence supporting {article_id}: {title}. Outcome sufficiency requires review.",
                asset_types=_soc2_assets(risk),
                source_url=NIST_CSF_2_SOURCE,
                official_source_ref="nist-csf-2.0",
            )
        )
    return specs


def _normalize_nist_control_id(control_id: str) -> str:
    return control_id.upper()


def _fedramp_moderate_row_transform(row: PackManifestRow) -> PackControlSpec:
    article_id = _normalize_nist_control_id(row.id)
    risk = nist_family_risk_domain(article_id)
    owner = _soc2_owner(risk)
    title = f"NIST 800-53B Moderate {article_id} — assessed from cloud posture and audit evidence"
    return PackControlSpec(
        control_id=f"FEDRAMP-{article_id}",
        framework_id="fedramp-moderate",
        framework="NIST 800-53B Moderate",
        framework_ref=f"NIST 800-53B Moderate {article_id}",
        article_id=article_id,
        title=title,
        risk_domain=risk,
        owner=owner,
        evaluation_rule=_soc2_evaluation_rule(risk),
        evidence_requirement=(
            f"Current evidence supports NIST 800-53B Moderate control {article_id} "
            "with reviewed mappings and fresh operational proof."
        ),
        asset_types=_soc2_assets(risk),
        source_url=FEDRAMP_SOURCE,
        official_source_ref="fedramp-moderate",
    )


def fedramp_moderate_specs() -> list[PackControlSpec]:
    """NIST 800-53B Moderate foundation: NIST SP 800-53 Rev 5 Moderate baseline (287 controls).

    Manifest-driven: identifiers come from ``nist_800_53_rev5_moderate.json``
    (``control_ids`` rows, plain strings — no per-ID title text exists at
    this baseline); ID normalization, risk-domain lookup, and title/evidence
    wording stay in :func:`_fedramp_moderate_row_transform`.
    """
    return pack_from_manifest(
        PACK_DATA_DIR / "nist_800_53_rev5_moderate.json",
        rows_key="control_ids",
        transform=_fedramp_moderate_row_transform,
    )


def _cis_aws_row_transform(row: PackManifestRow) -> PackControlSpec:
    req_id, req_title = row.id, row.title
    section = req_id.split(".", 1)[0]
    risk = cis_section_risk_domain(section)
    owner = _soc2_owner(risk)
    return PackControlSpec(
        control_id=f"CIS-AWS-{req_id}",
        framework_id="cis_aws",
        framework="CIS AWS Foundations Benchmark",
        framework_ref=f"CIS AWS Foundations {req_id}",
        article_id=req_id,
        title=req_title[:160],
        risk_domain=risk,
        owner=owner,
        evaluation_rule=_soc2_evaluation_rule(risk),
        evidence_requirement=(f"AWS posture evidence demonstrates CIS Foundations {req_id}: {req_title[:80]}"),
        asset_types=("cloud_resource", "cloud_policy", "iam_role", "identity_account", "s3_bucket"),
        source_url=CIS_AWS_SOURCE,
        official_source_ref="cis_aws",
    )


def cis_aws_v3_specs() -> list[PackControlSpec]:
    """All 62 CIS Amazon Web Services Foundations Benchmark v3.0.0 recommendations.

    Manifest-driven: identifiers/titles come from ``cis_aws_v3.json``
    (``requirements`` rows); risk-domain lookup and evidence wording stay in
    :func:`_cis_aws_row_transform`.
    """
    return pack_from_manifest(
        PACK_DATA_DIR / "cis_aws_v3.json", rows_key="requirements", transform=_cis_aws_row_transform
    )


def _iso_27001_row_transform(row: PackManifestRow) -> PackControlSpec:
    ref = row.id
    risk = iso_27001_theme_risk_domain(ref)
    owner = _soc2_owner(risk)
    title = f"ISO 27001:2022 {ref} — assessed from ISMS and security operations evidence"
    return PackControlSpec(
        control_id=f"ISO27001-{ref}",
        framework_id="iso-27001-2022",
        framework="ISO 27001:2022",
        framework_ref=f"ISO 27001:2022 {ref}",
        article_id=ref,
        title=title,
        risk_domain=risk,
        owner=owner,
        evaluation_rule=_soc2_evaluation_rule(risk),
        evidence_requirement=(
            f"Current evidence supports ISO 27001:2022 Annex A control {ref} "
            "with reviewed mappings and operational proof."
        ),
        asset_types=_soc2_assets(risk),
        source_url=ISO_27001_SOURCE,
        official_source_ref="iso-27001-2022",
    )


def iso_27001_2022_specs() -> list[PackControlSpec]:
    """All 93 ISO/IEC 27001:2022 Annex A controls.

    Manifest-driven: identifiers come from ``iso_27001_2022.json`` (``rows``,
    plain ``{"id": ...}`` entries — no distinct per-ID title text exists at
    this level, titles are fully formulaic); theme-prefix risk-domain lookup
    and title/evidence wording stay in :func:`_iso_27001_row_transform`.
    """
    return pack_from_manifest(PACK_DATA_DIR / "iso_27001_2022.json", transform=_iso_27001_row_transform)


def _cmmc_2_level2_row_transform(row: PackManifestRow) -> PackControlSpec:
    requirement_id, short_title = row.id, row.title
    risk = cmmc_800_171_family_risk_domain(requirement_id)
    owner = _soc2_owner(risk)
    return PackControlSpec(
        control_id=f"CMMC-{requirement_id}",
        framework_id="cmmc-2-level2",
        framework="CMMC 2.0 Level 2",
        framework_ref=f"NIST SP 800-171 Rev 2 {requirement_id}",
        article_id=requirement_id,
        title=f"CMMC L2 {requirement_id} — {short_title}",
        risk_domain=risk,
        owner=owner,
        evaluation_rule=_soc2_evaluation_rule(risk),
        evidence_requirement=(
            f"CUI protection evidence supports NIST SP 800-171 Rev 2 requirement {requirement_id} "
            f"({short_title}) for CMMC Level 2 assessment."
        ),
        asset_types=_soc2_assets(risk),
        source_url=CMMC_2_LEVEL2_SOURCE,
        official_source_ref="cmmc-2-level2",
    )


def cmmc_2_level2_specs() -> list[PackControlSpec]:
    """All 110 CMMC 2.0 Level 2 practices (NIST SP 800-171 Rev 2 requirements).

    Manifest-driven: identifiers/titles come from ``cmmc_2_level2.json``
    (``requirements`` rows, also read directly by ``sprs.py`` for SPRS
    scoring metadata); risk-domain lookup and title/evidence wording stay in
    :func:`_cmmc_2_level2_row_transform`.
    """
    return pack_from_manifest(
        PACK_DATA_DIR / "cmmc_2_level2.json", rows_key="requirements", transform=_cmmc_2_level2_row_transform
    )


def _iso_27017_row_transform(row: PackManifestRow) -> PackControlSpec:
    article_id, short_title = row.id, row.title
    risk = iso_27017_risk_domain(article_id)
    owner = _soc2_owner(risk)
    return PackControlSpec(
        control_id=f"ISO27017-{article_id}",
        framework_id="iso-27017-2015",
        framework="ISO 27017:2015",
        framework_ref=f"ISO 27017:2015 {article_id}",
        article_id=article_id,
        title=f"ISO 27017:2015 {article_id} — {short_title}",
        risk_domain=risk,
        owner=owner,
        evaluation_rule=_soc2_evaluation_rule(risk),
        evidence_requirement=(
            f"Cloud security evidence supports ISO 27017:2015 clause {article_id} "
            f"({short_title}) for shared CSP/CSC responsibilities."
        ),
        asset_types=_soc2_assets(risk),
        source_url=ISO_27017_SOURCE,
        official_source_ref="iso-27017-2015",
    )


def iso_27017_2015_specs() -> list[PackControlSpec]:
    """All 47 ISO/IEC 27017:2015 cloud security clause IDs (40 ISO 27002 + 7 CLD).

    Manifest-driven: identifiers/titles come from ``iso_27017_2015.json``
    (``controls`` rows); risk-domain lookup and title/evidence wording stay
    in :func:`_iso_27017_row_transform`.
    """
    return pack_from_manifest(
        PACK_DATA_DIR / "iso_27017_2015.json", rows_key="controls", transform=_iso_27017_row_transform
    )


def _iso_42001_row_transform(row: PackManifestRow) -> PackControlSpec:
    ref, short_title = row.id, row.title
    # Keep existing noncolliding IDs stable. The management clause 6.1.3
    # already owns the short ID; Annex A.6.1.3 is a separate obligation.
    article_id = ref if ref == "A.6.1.3" else ref.removeprefix("A.")
    return PackControlSpec(
        control_id=f"ISO42001-{article_id}",
        framework_id="iso-42001-2023",
        framework="ISO 42001:2023",
        framework_ref=f"ISO 42001:2023 {ref}",
        article_id=article_id,
        title=short_title,
        risk_domain="ai-governance",
        owner="ai-security",
        evaluation_rule="fail_when_open_violation_or_stale_evidence",
        evidence_requirement=(f"AI governance evidence supports ISO 42001:2023 control {ref} ({short_title})."),
        asset_types=("ai_model", "ai_agent", "service", "data_store", "audit_log"),
        source_url=ISO_42001_SOURCE,
        official_source_ref="iso-42001-2023",
        reconciled_at="2026-10-06" if ref == "A.6.1.3" else None,
    )


def iso_42001_2023_specs() -> list[PackControlSpec]:
    """All 38 ISO/IEC 42001:2023 Annex A AI management controls.

    Manifest-driven: identifiers/titles come from ``iso_42001_2023.json``
    (moved out of the ``ISO_42001_CONTROLS`` Python tuple); the "A." prefix
    strip for ``article_id``/``control_id`` stays in
    :func:`_iso_42001_row_transform`.
    """
    return pack_from_manifest(PACK_DATA_DIR / "iso_42001_2023.json", transform=_iso_42001_row_transform)


def _nist_800_53_row_transform(row: PackManifestRow) -> PackControlSpec:
    article_id = row.id
    risk = nist_family_risk_domain(article_id)
    return PackControlSpec(
        control_id=f"NIST-800-53-{article_id}",
        framework_id="nist-800-53-rev5",
        framework="NIST SP 800-53 Rev 5",
        framework_ref=f"NIST SP 800-53 Rev 5 {article_id}",
        article_id=article_id,
        title=f"{article_id} — {row.title}",
        risk_domain=risk,
        owner=_soc2_owner(risk),
        evaluation_rule=_soc2_evaluation_rule(risk),
        evidence_requirement=(
            f"Current evidence supports NIST SP 800-53 Rev 5 control {article_id} "
            "with reviewed mappings and fresh operational proof."
        ),
        asset_types=_soc2_assets(risk),
        source_url=NIST_800_53_SOURCE,
        official_source_ref="nist-800-53-rev5",
        baselines=tuple(row.extra.get("baselines") or ()),
    )


def nist_800_53_rev5_specs() -> list[PackControlSpec]:
    """Every active NIST SP 800-53 Rev 5 control and enhancement (1,014 at 5.2.0).

    Generated from the pinned official OSCAL catalog by
    ``tools/sync_nist_800_53.py``; each row carries its LOW/MODERATE/HIGH/PRIVACY
    baseline membership.
    """
    return pack_from_manifest(PACK_DATA_DIR / "nist_800_53_rev5_catalog.json", transform=_nist_800_53_row_transform)


def _nist_rmf_row_transform(row: PackManifestRow) -> PackControlSpec:
    task_id = row.id
    risk = RMF_STEP_RISK_DOMAIN[task_id[0]]
    step = str(row.extra.get("step") or "")
    return PackControlSpec(
        control_id=f"NIST-RMF-{task_id}",
        framework_id="nist-rmf-800-37r2",
        framework="NIST RMF (SP 800-37 Rev 2)",
        framework_ref=f"NIST SP 800-37 Rev 2 Task {task_id}",
        article_id=task_id,
        title=f"{step} {task_id} — {row.title}"[:240],
        risk_domain=risk,
        owner=_soc2_owner(risk),
        evaluation_rule=_soc2_evaluation_rule(risk),
        evidence_requirement=f"Current evidence shows RMF task {task_id} ({step} step) is performed and recorded.",
        asset_types=_soc2_assets(risk),
        source_url=NIST_RMF_SOURCE,
        official_source_ref="nist-rmf-800-37r2",
    )


def nist_rmf_800_37r2_specs() -> list[PackControlSpec]:
    """All 47 NIST Risk Management Framework tasks (SP 800-37 Rev 2), by step."""
    return pack_from_manifest(PACK_DATA_DIR / "nist_rmf_800_37r2.json", transform=_nist_rmf_row_transform)


def _nist_800_171_r3_row_transform(row: PackManifestRow) -> PackControlSpec:
    requirement_id = row.id
    risk = str(row.extra["risk_domain"])
    return PackControlSpec(
        control_id=f"NIST-800-171R3-{requirement_id}",
        framework_id="nist-800-171-rev3",
        framework="NIST SP 800-171 Rev 3",
        framework_ref=f"NIST SP 800-171 Rev 3 {requirement_id}",
        article_id=requirement_id,
        title=f"{requirement_id} — {row.title}",
        risk_domain=risk,
        owner=_soc2_owner(risk),
        evaluation_rule=_soc2_evaluation_rule(risk),
        evidence_requirement=(
            f"CUI protection evidence supports NIST SP 800-171 Rev 3 requirement {requirement_id} ({row.title})."
        ),
        asset_types=_soc2_assets(risk),
        source_url=NIST_800_171_R3_SOURCE,
        official_source_ref="nist-800-171-rev3",
        required_evidence_types=tuple(row.extra["required_evidence_types"]),
    )


def nist_800_171_rev3_specs() -> list[PackControlSpec]:
    """All 97 NIST SP 800-171 Rev 3 security requirements across 17 families.

    Generated from the pinned official OSCAL catalog by
    ``tools/sync_nist_800_171r3.py``; each row records its Rev 2 predecessors
    from NIST's published change analysis.
    """
    return pack_from_manifest(PACK_DATA_DIR / "nist_800_171_rev3.json", transform=_nist_800_171_r3_row_transform)


PACK_BUILDERS: dict[str, Callable[[], Iterable[PackControlSpec]]] = {
    "soc2": soc2_full_pack_specs,
    "nist-ai-rmf": nist_ai_rmf_specs,
    "nist-csf-2.0": nist_csf_2_specs,
    "fedramp-moderate": fedramp_moderate_specs,
    "cis-aws": cis_aws_v3_specs,
    "cmmc-2-level2": cmmc_2_level2_specs,
    "iso-27001-2022": iso_27001_2022_specs,
    "iso-27017-2015": iso_27017_2015_specs,
    "iso-42001-2023": iso_42001_2023_specs,
    "nist-800-53-rev5": nist_800_53_rev5_specs,
    "nist-rmf-800-37r2": nist_rmf_800_37r2_specs,
    "nist-800-171-rev3": nist_800_171_rev3_specs,
}

from security_lakehouse.limited_packs import LIMITED_PACK_BUILDERS  # noqa: E402

PACK_BUILDERS = {**PACK_BUILDERS, **LIMITED_PACK_BUILDERS}


def _review_fields(spec: PackControlSpec) -> tuple[str | None, str, str | None]:
    """(reviewed_by, review_status, reviewed date) for a generated pack row."""
    reconciled = spec.reconciled_at or SOURCE_RECONCILED_PACKS.get(spec.framework_id)
    if reconciled:
        return SOURCE_RECONCILED_BY, "proposed", reconciled
    if spec.framework_id in PROPOSED_SOURCE_FRAMEWORKS:
        return None, "proposed", None
    return REVIEWED_BY, "reviewed", REVIEWED_DATE


def pack_control_row(spec: PackControlSpec) -> JsonObject:
    reconciled = spec.reconciled_at or SOURCE_RECONCILED_PACKS.get(spec.framework_id)
    reviewed_by, review_status, reviewed_date = _review_fields(spec)
    return {
        "control_id": spec.control_id,
        "framework_id": spec.framework_id,
        "framework": spec.framework,
        "title": spec.title,
        "risk_domain": spec.risk_domain,
        "owner": spec.owner,
        "evidence_requirement": spec.evidence_requirement,
        "evaluation_rule": spec.evaluation_rule,
        "frequency": "continuous",
        "implementation_status": "implemented_limited_mapping"
        if spec.framework_id in PROPOSED_SOURCE_FRAMEWORKS
        else "implemented",
        "version": "1.0.0",
        "valid_from": reconciled or REVIEWED_DATE,
        "valid_to": None,
        "supersedes": None,
        "superseded_by": None,
        "change_reason": "Reconciled identifier and title with the pinned official source"
        if reconciled
        else "Framework pack sync",
        "lifecycle_status": "active",
        "official_source_ref": spec.official_source_ref,
        "framework_ref": spec.framework_ref,
        "source_url": spec.source_url,
        "mapping_rationale": "Direct source identity; not a cross-framework equivalence or certification assertion."
        if reconciled
        else f"Pack mapping: control identifier matches {spec.framework_ref} verbatim.",
        "reviewed_by": reviewed_by,
        "review_status": review_status,
        "reviewed_date": reviewed_date,
        "signal_source": "silver/normalized_events.jsonl",
        "asset_types": list(spec.asset_types),
        **({"nist_baselines": list(spec.baselines)} if spec.framework_id == "nist-800-53-rev5" else {}),
        **({"required_evidence_types": list(spec.required_evidence_types)} if spec.required_evidence_types else {}),
    }


def pack_mapping_row(spec: PackControlSpec) -> JsonObject:
    reviewed_by, review_status, reviewed_date = _review_fields(spec)
    return {
        "control_id": spec.control_id,
        "framework_id": spec.framework_id,
        "articles": [
            {
                "article_id": spec.article_id,
                "title": spec.title[:120],
                "official_source_url": spec.source_url,
                "reviewed_by": reviewed_by,
                "review_status": review_status,
                "reviewed_at": f"{reviewed_date}T00:00:00Z" if reviewed_date else None,
                "rationale": f"Pack mapping to {spec.framework_ref}.",
            }
        ],
    }


def pack_control_map_row(spec: PackControlSpec) -> JsonObject:
    return {
        "control_id": spec.control_id,
        "framework": spec.framework,
        "title": spec.title[:120],
        "risk_domain": spec.risk_domain,
        "owner": spec.owner,
    }


def _read_json(path: Path) -> JsonObject:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: Path, payload: JsonObject) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def _regenerate_verified_article_ids(mappings_payload: JsonObject, *, path: Path) -> None:
    """Rebuild the verified article allowlist from active mappings."""
    framework_article_ids: dict[str, list[str]] = {}
    for row in mappings_payload.get("mappings", []):
        framework_id = str(row["framework_id"])
        known = set(framework_article_ids.get(framework_id, []))
        for article in row.get("articles", []):
            article_id = str(article["article_id"])
            if article_id not in known:
                known.add(article_id)
                framework_article_ids.setdefault(framework_id, []).append(article_id)
    for framework_id, ids in framework_article_ids.items():
        framework_article_ids[framework_id] = sorted(ids)

    existing = _read_json(path) if path.is_file() else {}
    payload = {
        "schema": "trustops.verified_article_ids.v1",
        "note": existing.get(
            "note",
            (
                "Audit-verified, real control/article identifiers per framework. "
                "Any NEW mapping article_id must be added here, forcing human verification "
                "against the official source. Regenerated from mappings/control_articles.json "
                "by frameworks sync-packs."
            ),
        ),
        "framework_article_ids": dict(sorted(framework_article_ids.items())),
    }
    _write_json(path, payload)


def sync_framework_packs(
    *,
    packs: list[str] | None = None,
    catalog_path: Path | None = None,
    mappings_path: Path | None = None,
    control_map_path: Path | None = None,
    write_bundle: bool = True,
) -> dict[str, Any]:
    """Merge selected packs into catalog artifacts. Preserves hand-authored rows."""
    selected = packs or list(PACK_BUILDERS.keys())
    catalog_path = catalog_path or DEFAULT_CONTROL_CATALOG
    mappings_path = mappings_path or DEFAULT_MAPPINGS
    control_map_path = control_map_path or DEFAULT_CONTROL_CATALOG.parent.parent / "mappings" / "control_map.json"

    catalog_payload = _read_json(catalog_path)
    mappings_payload = _read_json(mappings_path)
    control_map_payload = _read_json(control_map_path)

    existing_controls = {str(row["control_id"]): row for row in catalog_payload.get("controls", [])}
    existing_mappings = {str(row["control_id"]): row for row in mappings_payload.get("mappings", [])}
    existing_map = {str(row["control_id"]): row for row in control_map_payload.get("controls", [])}

    added_controls = 0
    added_mappings = 0
    for pack_id in selected:
        builder = PACK_BUILDERS.get(pack_id)
        if builder is None:
            raise ValueError(f"unknown pack {pack_id!r}; choose from {sorted(PACK_BUILDERS)}")
        for spec in builder():
            if spec.control_id not in existing_controls:
                existing_controls[spec.control_id] = pack_control_row(spec)
                added_controls += 1
            if spec.control_id not in existing_mappings:
                existing_mappings[spec.control_id] = pack_mapping_row(spec)
                added_mappings += 1
            if spec.control_id not in existing_map:
                existing_map[spec.control_id] = pack_control_map_row(spec)

    catalog_payload["controls"] = sorted(existing_controls.values(), key=lambda row: str(row["control_id"]))
    catalog_payload["catalog_version"] = REVIEWED_DATE
    catalog_payload["scope"] = PACK_SCOPE

    mappings_payload["mappings"] = sorted(existing_mappings.values(), key=lambda row: str(row["control_id"]))
    control_map_payload["controls"] = sorted(existing_map.values(), key=lambda row: str(row["control_id"]))

    _write_json(catalog_path, catalog_payload)
    _write_json(mappings_path, mappings_payload)
    _write_json(control_map_path, control_map_payload)

    bundle = None
    if write_bundle:
        bundle = write_bundle_lock(lock_path=DEFAULT_BUNDLE_LOCK_PATH)
        _regenerate_verified_article_ids(mappings_payload, path=DEFAULT_VERIFIED_ARTICLE_IDS)

    framework_counts = {
        framework_id: sum(1 for row in catalog_payload["controls"] if row.get("framework_id") == framework_id)
        for framework_id in (
            "soc2",
            "nist-ai-rmf",
            "nist-csf-2.0",
            "fedramp-moderate",
            "cis_aws",
            "cmmc-2-level2",
            "iso-27001-2022",
            "iso-27017-2015",
            "iso-42001-2023",
            "gdpr-2016-679",
            "hipaa-security-rule",
            "pci-dss-v4",
            "eu-ai-act-2024-1689",
        )
    }
    return {
        "packs": selected,
        "added_controls": added_controls,
        "added_mappings": added_mappings,
        "control_count": len(catalog_payload["controls"]),
        "soc2_control_count": framework_counts["soc2"],
        "nist_ai_rmf_control_count": framework_counts["nist-ai-rmf"],
        "nist_csf_2_control_count": framework_counts["nist-csf-2.0"],
        "fedramp_moderate_control_count": framework_counts["fedramp-moderate"],
        "cis_aws_control_count": framework_counts["cis_aws"],
        "cmmc_2_level2_control_count": framework_counts["cmmc-2-level2"],
        "iso_27001_control_count": framework_counts["iso-27001-2022"],
        "iso_27017_control_count": framework_counts["iso-27017-2015"],
        "iso_42001_control_count": framework_counts["iso-42001-2023"],
        "framework_counts": framework_counts,
        "bundle_hash": bundle.get("components", {}).get("controls") if bundle else None,
    }
