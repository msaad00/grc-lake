"""Static pack data for FedRAMP, CIS AWS, and ISO framework full packs."""

from __future__ import annotations

import json
from functools import lru_cache

from security_lakehouse.catalog import ROOT

PACK_DATA_DIR = ROOT / "frameworks" / "packs" / "data"

FEDRAMP_MODERATE_COUNT = 287
CMMC_2_LEVEL2_COUNT = 110
CIS_AWS_V3_COUNT = 62
ISO_27001_2022_ANNEX_A_COUNT = 93
ISO_27017_2015_COUNT = 47
ISO_42001_2023_ANNEX_A_COUNT = 38

NIST_CSF_2_COUNT = 106

FEDRAMP_SOURCE = "https://csrc.nist.gov/publications/detail/sp/800-53b/final"
CMMC_2_LEVEL2_SOURCE = "https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final"
CMMC_PROGRAM_SOURCE = "https://dodcio.defense.gov/CMMC/Documentation/"
CIS_AWS_SOURCE = "https://www.cisecurity.org/benchmark/amazon_web_services"
ISO_27001_SOURCE = "https://www.iso.org/standard/27001"
ISO_27017_SOURCE = "https://www.iso.org/standard/43757.html"
ISO_42001_SOURCE = "https://www.iso.org/standard/42001"
NIST_CSF_2_SOURCE = "https://www.nist.gov/cyberframework"


@lru_cache(maxsize=1)
def cmmc_2_level2_requirements() -> tuple[tuple[str, str], ...]:
    path = PACK_DATA_DIR / "cmmc_2_level2.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    return tuple((str(row["id"]).strip(), str(row["title"])) for row in payload["requirements"])


@lru_cache(maxsize=1)
def iso_27017_2015_controls() -> tuple[tuple[str, str], ...]:
    path = PACK_DATA_DIR / "iso_27017_2015.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    return tuple((str(row["id"]), str(row["title"])) for row in payload["controls"])


@lru_cache(maxsize=1)
def cis_aws_v3_requirements() -> tuple[tuple[str, str], ...]:
    path = PACK_DATA_DIR / "cis_aws_v3.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    return tuple((str(row["id"]), str(row["title"])) for row in payload["requirements"])


def nist_family_risk_domain(control_id: str) -> str:
    family = control_id.split("-")[0].upper()
    return {
        "AC": "identity",
        "AT": "governance",
        "AU": "monitoring",
        "CA": "risk-management",
        "CM": "controls-operations",
        "CP": "change-management",
        "IA": "identity",
        "IR": "monitoring",
        "MA": "controls-operations",
        "MP": "controls-operations",
        "PE": "change-management",
        "PL": "governance",
        "PM": "governance",
        "PS": "governance",
        "PT": "governance",
        "RA": "risk-management",
        "SA": "controls-operations",
        "SC": "controls-operations",
        "SI": "monitoring",
        "SR": "vendor-risk",
    }.get(family, "governance")


def cmmc_800_171_family_risk_domain(requirement_id: str) -> str:
    family = ".".join(requirement_id.split(".")[:2])
    return {
        "3.1": "identity",
        "3.2": "governance",
        "3.3": "monitoring",
        "3.4": "controls-operations",
        "3.5": "identity",
        "3.6": "monitoring",
        "3.7": "change-management",
        "3.8": "controls-operations",
        "3.9": "governance",
        "3.10": "change-management",
        "3.11": "risk-management",
        "3.12": "risk-management",
        "3.13": "controls-operations",
        "3.14": "monitoring",
    }.get(family, "governance")


def iso_27001_theme_risk_domain(ref: str) -> str:
    if ref.startswith("A.5."):
        return "governance"
    if ref.startswith("A.6."):
        return "governance"
    if ref.startswith("A.7."):
        return "change-management"
    return "controls-operations"


def iso_27017_risk_domain(article_id: str) -> str:
    if article_id.startswith("CLD."):
        cld = {
            "CLD.6.3.1": "vendor-risk",
            "CLD.8.1.5": "change-management",
            "CLD.9.5.1": "controls-operations",
            "CLD.9.5.2": "controls-operations",
            "CLD.12.1.5": "identity",
            "CLD.12.4.5": "monitoring",
            "CLD.13.1.4": "controls-operations",
        }
        return cld.get(article_id, "controls-operations")
    section = int(article_id.split(".", 1)[0])
    return {
        5: "governance",
        6: "governance",
        7: "governance",
        8: "controls-operations",
        9: "identity",
        10: "controls-operations",
        11: "change-management",
        12: "monitoring",
        13: "controls-operations",
        14: "change-management",
        15: "vendor-risk",
        16: "monitoring",
        17: "change-management",
        18: "governance",
    }.get(section, "controls-operations")


def cis_section_risk_domain(section: str) -> str:
    return {
        "1": "identity",
        "2": "controls-operations",
        "3": "monitoring",
        "4": "monitoring",
        "5": "controls-operations",
    }.get(section, "controls-operations")


def csf_category_risk_domain(function: str, category: str) -> str:
    """Map NIST CSF 2.0 function/category pairs to TrustOps risk domains."""
    key = f"{function}.{category}"
    return {
        "GV.OC": "governance",
        "GV.RM": "risk-management",
        "GV.RR": "governance",
        "GV.PO": "governance",
        "GV.OV": "governance",
        "GV.SC": "vendor-risk",
        "ID.AM": "controls-operations",
        "ID.RA": "risk-management",
        "ID.IM": "risk-management",
        "PR.AA": "identity",
        "PR.AT": "governance",
        "PR.DS": "controls-operations",
        "PR.PS": "controls-operations",
        "PR.IR": "change-management",
        "DE.CM": "monitoring",
        "DE.AE": "monitoring",
        "RS.MA": "monitoring",
        "RS.AN": "monitoring",
        "RS.CO": "monitoring",
        "RS.MI": "monitoring",
        "RC.RP": "change-management",
        "RC.CO": "change-management",
    }.get(key, "governance")


def nist_csf_2_outcomes() -> dict[str, str]:
    """Official public CSF 2.0 outcome text, pinned with source digest."""
    payload = json.loads((PACK_DATA_DIR / "nist_csf_2_core.json").read_text(encoding="utf-8"))
    return dict(payload["outcomes"])
