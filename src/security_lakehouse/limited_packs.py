"""Limited-mapping framework packs: GDPR, HIPAA, PCI DSS, EU AI Act, CIS Controls, ISO 27701, NIS2, DORA.

Expands honest seed subsets toward managed-GRC breadth without claiming
full official catalog coverage. Each control maps to a single official article
or CFR section with short internal titles only.

Manifest-driven: each pack's identifiers, titles, risk domain, owner, and
asset types are data in ``frameworks/packs/data/*.json`` (one row per
official article/section — no lookup lives in code, since these packs are
flat by construction). ``_limited_row_transform`` is the small shared
transform that turns a manifest row into a :class:`PackControlSpec`.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable

from security_lakehouse.pack_data import PACK_DATA_DIR
from security_lakehouse.pack_manifest import PackManifestRow, pack_from_manifest
from security_lakehouse.pack_spec import PackControlSpec

GDPR_SOURCE = "https://eur-lex.europa.eu/eli/reg/2016/679/oj"
HIPAA_SOURCE = "https://www.hhs.gov/hipaa/for-professionals/security/index.html"
PCI_SOURCE = "https://www.pcisecuritystandards.org/document_library/?category=pcidss"
EU_AI_ACT_SOURCE = "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=OJ:L_202401689"
CIS_CONTROLS_SOURCE = "https://www.cisecurity.org/controls/v8-1"
ISO_27701_SOURCE = "https://www.iso.org/standard/27701"
NIS2_SOURCE = "https://eur-lex.europa.eu/eli/dir/2022/2555/oj"
DORA_SOURCE = "https://eur-lex.europa.eu/eli/reg/2022/2554/oj"
_EU_ARTICLE_ID = re.compile(r"^Art(\d+)(?:\.(\d+)(?:\(([a-z])\))?)?$")


def eu_article_ref(article_id: str) -> str:
    """Render a pack id such as ``Art21.2(a)`` as the EU citation ``Article 21(2)(a)``."""
    match = _EU_ARTICLE_ID.match(article_id)
    if match is None:
        raise ValueError(f"not an EU article identifier: {article_id!r}")
    article, paragraph, point = match.groups()
    return f"Article {article}" + (f"({paragraph})" if paragraph else "") + (f"({point})" if point else "")


def _limited_row_transform(
    row: PackManifestRow,
    *,
    framework_id: str,
    framework: str,
    control_id_prefix: str,
    framework_ref: Callable[[str], str],
    source_url: str,
    article_id: Callable[[str], str] | None = None,
    evidence_requirement: Callable[[str, str], str] | None = None,
) -> PackControlSpec:
    ref = row.id
    resolved_article_id = article_id(ref) if article_id is not None else ref
    resolved_framework_ref = framework_ref(ref)
    return PackControlSpec(
        control_id=f"{control_id_prefix}-{ref}",
        framework_id=framework_id,
        framework=framework,
        framework_ref=resolved_framework_ref,
        article_id=resolved_article_id,
        title=row.title,
        risk_domain=str(row.extra["risk_domain"]),
        owner=str(row.extra["owner"]),
        evaluation_rule="fail_when_stale_evidence",
        evidence_requirement=(
            evidence_requirement(resolved_framework_ref, row.title)
            if evidence_requirement is not None
            else f"Evidence for {resolved_framework_ref} exists within freshness SLA."
        ),
        asset_types=tuple(row.extra["asset_types"]),
        source_url=source_url,
        official_source_ref=framework_id,
        required_evidence_types=tuple(row.extra.get("required_evidence_types", ())),
        reconciled_at=row.extra.get("source_reconciled_at"),
    )


def gdpr_limited_pack_specs() -> Iterable[PackControlSpec]:
    return pack_from_manifest(
        PACK_DATA_DIR / "gdpr_2016_679.json",
        transform=lambda row: _limited_row_transform(
            row,
            framework_id="gdpr-2016-679",
            framework="GDPR",
            control_id_prefix="GDPR",
            framework_ref=lambda ref: f"GDPR {ref}",
            source_url=GDPR_SOURCE,
        ),
    )


def hipaa_limited_pack_specs() -> Iterable[PackControlSpec]:
    return pack_from_manifest(
        PACK_DATA_DIR / "hipaa_security_rule.json",
        transform=lambda row: _limited_row_transform(
            row,
            framework_id="hipaa-security-rule",
            framework="HIPAA",
            control_id_prefix="HIPAA",
            framework_ref=lambda ref: f"45 CFR §{ref}",
            source_url=HIPAA_SOURCE,
        ),
    )


def pci_dss_limited_pack_specs() -> Iterable[PackControlSpec]:
    return pack_from_manifest(
        PACK_DATA_DIR / "pci_dss_v4.json",
        transform=lambda row: _limited_row_transform(
            row,
            framework_id="pci-dss-v4",
            framework="PCI DSS",
            control_id_prefix="PCI-DSS",
            framework_ref=lambda ref: f"PCI DSS v4.0.1 Req {ref}",
            source_url=PCI_SOURCE,
            article_id=lambda ref: f"Req-{ref}",
        ),
    )


def eu_ai_act_limited_pack_specs() -> Iterable[PackControlSpec]:
    return pack_from_manifest(
        PACK_DATA_DIR / "eu_ai_act_2024_1689.json",
        transform=lambda row: _limited_row_transform(
            row,
            framework_id="eu-ai-act-2024-1689",
            framework="EU AI Act",
            control_id_prefix="EU-AI-ACT",
            framework_ref=lambda ref: f"EU AI Act {ref}",
            source_url=EU_AI_ACT_SOURCE,
        ),
    )


def cis_controls_v8_1_limited_pack_specs() -> Iterable[PackControlSpec]:
    return pack_from_manifest(
        PACK_DATA_DIR / "cis_controls_v8_1.json",
        transform=lambda row: _limited_row_transform(
            row,
            framework_id="cis-controls-v8.1",
            framework="CIS Controls",
            control_id_prefix="CIS-CONTROLS",
            framework_ref=lambda ref: f"CIS Controls v8.1 Control {ref}",
            source_url=CIS_CONTROLS_SOURCE,
            article_id=lambda ref: f"Control-{ref}",
        ),
    )


def iso_27701_2025_limited_pack_specs() -> Iterable[PackControlSpec]:
    """ISO/IEC 27701:2025 Annex A controls verified by two independent non-vendor sources.

    ``iso_27701_2025.json`` lists the seeded rows and, under ``gaps``, the
    Annex A identifiers still awaiting a second source; only ``rows`` are built.
    """
    return pack_from_manifest(
        PACK_DATA_DIR / "iso_27701_2025.json",
        transform=lambda row: _limited_row_transform(
            row,
            framework_id="iso-27701-2025",
            framework="ISO 27701:2025",
            control_id_prefix="ISO27701",
            framework_ref=lambda ref: f"ISO/IEC 27701:2025 {ref}",
            source_url=ISO_27701_SOURCE,
            evidence_requirement=lambda ref, title: (
                f"Current privacy evidence supports {ref} ({title}) within the freshness SLA."
            ),
        ),
    )


def _eu_act_specs(
    manifest: str, *, framework_id: str, framework: str, prefix: str, act: str, source: str
) -> list[PackControlSpec]:
    return pack_from_manifest(
        PACK_DATA_DIR / manifest,
        transform=lambda row: _limited_row_transform(
            row,
            framework_id=framework_id,
            framework=framework,
            control_id_prefix=prefix,
            framework_ref=lambda ref: f"{act} {eu_article_ref(ref)}",
            source_url=source,
            evidence_requirement=lambda ref, title: (
                f"Current evidence supports {ref} ({title}) within the freshness SLA."
            ),
        ),
    )


def nis2_limited_pack_specs() -> Iterable[PackControlSpec]:
    """NIS2 Article 21(2)(a)-(j) risk-management measures and Article 23 entity reporting obligations."""
    return _eu_act_specs(
        "nis2_2022_2555.json",
        framework_id="nis2-2022-2555",
        framework="NIS2 Directive",
        prefix="NIS2",
        act="Directive (EU) 2022/2555",
        source=NIS2_SOURCE,
    )


def dora_limited_pack_specs() -> Iterable[PackControlSpec]:
    """DORA entity obligations: ICT risk management, incidents, testing, third-party risk, information sharing."""
    return _eu_act_specs(
        "dora_2022_2554.json",
        framework_id="dora-2022-2554",
        framework="DORA",
        prefix="DORA",
        act="Regulation (EU) 2022/2554",
        source=DORA_SOURCE,
    )


LIMITED_PACK_BUILDERS = {
    "gdpr": gdpr_limited_pack_specs,
    "hipaa": hipaa_limited_pack_specs,
    "pci-dss": pci_dss_limited_pack_specs,
    "eu-ai-act": eu_ai_act_limited_pack_specs,
    "cis-controls": cis_controls_v8_1_limited_pack_specs,
    "iso-27701": iso_27701_2025_limited_pack_specs,
    "nis2": nis2_limited_pack_specs,
    "dora": dora_limited_pack_specs,
}

# Expected minimum seeded counts after limited pack sync (existing + new).
LIMITED_PACK_MINIMUMS = {
    "gdpr-2016-679": 20,
    "hipaa-security-rule": 18,
    "pci-dss-v4": 12,
    "eu-ai-act-2024-1689": 15,
    "cis-controls-v8.1": 18,
    "iso-27701-2025": 10,
    "nis2-2022-2555": 17,
    "dora-2022-2554": 99,
}
