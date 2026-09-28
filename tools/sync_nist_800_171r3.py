"""Regenerate the NIST SP 800-171 Rev 3 pack manifest from official NIST sources.

Reads the Rev 3 OSCAL catalog from a pinned commit of
https://github.com/usnistgov/oscal-content and NIST's published Rev 2 -> Rev 3
change analysis workbook, then writes
``frameworks/packs/data/nist_800_171_rev3.json`` with every active (non-withdrawn)
requirement, its official title and family, and its Rev 2 predecessors as NIST's
analysis states them. Every Rev 2 requirement is accounted for, either as a
predecessor or as not carried forward with NIST's stated reason.

The sha256 of each source is recorded. The CCF ``unmapped`` list is curated in
the manifest and preserved across regenerations.

Usage::

    uv run python tools/sync_nist_800_171r3.py
    uv run python tools/sync_nist_800_171r3.py --source-dir <dir with the three downloaded files>
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import urllib.request
import zipfile
from datetime import date
from pathlib import Path
from typing import IO, Any
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "frameworks" / "packs" / "data" / "nist_800_171_rev3.json"
CMMC_MANIFEST = ROOT / "frameworks" / "packs" / "data" / "cmmc_2_level2.json"

OSCAL_COMMIT = "78650f02ad9321bb7b817846f8fbd4f2bcd620de"
CATALOG_FILE = "NIST_SP800-171_rev3_catalog.json"
CATALOG_URL = (
    f"https://raw.githubusercontent.com/usnistgov/oscal-content/{OSCAL_COMMIT}/nist.gov/SP800-171/rev3/json/"
    + CATALOG_FILE
)
PUBLICATION_URL = "https://csrc.nist.gov/pubs/sp/800/171/r3/final"
PDF_URL = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r3.pdf"
ANALYSIS_URL = "https://csrc.nist.gov/files/pubs/sp/800/171/r3/final/docs/sp800-171r2-to-r3-analysis.xlsx"
ANALYSIS_SHEET = "Change Analysis 800-171 R2-R3"
FILES = {"catalog": CATALOG_URL, "pdf": PDF_URL, "analysis": ANALYSIS_URL}
LOCAL_NAMES = {"catalog": CATALOG_FILE, "pdf": "NIST.SP.800-171r3.pdf", "analysis": "sp800-171r2-to-r3-analysis.xlsx"}

# Catalog risk domain (drives connector hints and evaluation rules) and the
# evidence types a requirement in each family is tested with.
FAMILY_PROFILE: dict[str, tuple[str, tuple[str, ...]]] = {
    "03.01": ("identity", ("identity.access_review", "cloud.config")),
    "03.02": ("governance", ("compliance.evidence_bundle",)),
    "03.03": ("monitoring", ("audit.chain", "cloud.config")),
    "03.04": ("controls-operations", ("cloud.config",)),
    "03.05": ("identity", ("identity.access_review", "cloud.config")),
    "03.06": ("monitoring", ("detection.alert", "remediation.ticket")),
    "03.07": ("controls-operations", ("compliance.evidence_bundle", "remediation.ticket")),
    "03.08": ("controls-operations", ("cloud.config", "compliance.evidence_bundle")),
    "03.09": ("governance", ("identity.access_review", "compliance.evidence_bundle")),
    "03.10": ("controls-operations", ("compliance.evidence_bundle",)),
    "03.11": ("risk-management", ("vulnerability.finding", "compliance.evidence_bundle")),
    "03.12": ("risk-management", ("compliance.evidence_bundle", "remediation.ticket")),
    "03.13": ("controls-operations", ("cloud.config",)),
    "03.14": ("monitoring", ("vulnerability.finding", "detection.alert")),
    "03.15": ("governance", ("compliance.evidence_bundle",)),
    "03.16": ("controls-operations", ("compliance.evidence_bundle",)),
    "03.17": ("vendor-risk", ("compliance.evidence_bundle",)),
}

_NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
_REL_NS = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"
_R3_ID = re.compile(r"03\.\d{2}[ .]?\d{2}")


def _fetch(name: str, source_dir: Path | None) -> bytes:
    if source_dir is not None:
        return (source_dir / LOCAL_NAMES[name]).read_bytes()
    with urllib.request.urlopen(FILES[name], timeout=60) as resp:  # noqa: S310 - pinned https sources
        return bytes(resp.read())


def _column(ref: str) -> int:
    index = 0
    for char in re.match(r"[A-Z]+", ref).group(0):  # type: ignore[union-attr]
        index = index * 26 + ord(char) - 64
    return index - 1


def read_xlsx_rows(source: Path | IO[bytes], sheet_name: str = ANALYSIS_SHEET) -> list[list[str]]:
    """Read one worksheet of an .xlsx as rows of stripped strings (stdlib only)."""
    with zipfile.ZipFile(source) as archive:
        names = set(archive.namelist())
        shared: list[str] = []
        if "xl/sharedStrings.xml" in names:
            root = ElementTree.fromstring(archive.read("xl/sharedStrings.xml"))
            shared = ["".join(t.text or "" for t in si.iter(f"{{{_NS['m']}}}t")) for si in root.findall("m:si", _NS)]
        workbook = ElementTree.fromstring(archive.read("xl/workbook.xml"))
        rels = ElementTree.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
        targets = {rel.get("Id"): rel.get("Target") for rel in rels}
        sheets = workbook.find("m:sheets", _NS)
        sheet = next(s for s in (sheets if sheets is not None else []) if s.get("name") == sheet_name)
        target = str(targets[sheet.get(_REL_NS)]).lstrip("/")
        target = target if target.startswith("xl/") else f"xl/{target}"
        root = ElementTree.fromstring(archive.read(target))
    rows: list[list[str]] = []
    for row in root.iter(f"{{{_NS['m']}}}row"):
        values: dict[int, str] = {}
        for cell in row.findall("m:c", _NS):
            kind = cell.get("t")
            if kind == "inlineStr":
                text = "".join(t.text or "" for t in cell.iter(f"{{{_NS['m']}}}t"))
            else:
                raw = cell.find("m:v", _NS)
                text = raw.text or "" if raw is not None else ""
                if kind == "s" and text:
                    text = shared[int(text)]
            values[_column(str(cell.get("r")))] = text.strip()
        width = max(values) + 1 if values else 0
        rows.append([values.get(i, "") for i in range(width)])
    return rows


def parse_analysis_rows(rows: list[list[str]]) -> list[dict[str, Any]]:
    """Parse the change analysis sheet: one dict per Rev 2 / Rev 3 row."""
    flags = ("none", "significant", "minor", "new_odp", "new", "withdrawn")
    parsed: list[dict[str, Any]] = []
    for row in rows[1:]:
        row = row + [""] * (16 - len(row))
        r3 = row[6].strip()
        if not r3:
            continue
        marked = {flag for flag, value in zip(flags, row[9:15], strict=True) if value.upper() == "X"}
        withdrawn = row[7] == "Withdrawn" or "withdrawn" in marked
        parsed.append(
            {
                "r2": row[2].strip(),
                "r3": r3,
                "name": row[7],
                "withdrawn": withdrawn,
                "withdrawn_text": row[8].strip() if withdrawn else "",
                "change": next((f for f in ("significant", "minor", "none") if f in marked), "new")
                if not withdrawn
                else "withdrawn",
            }
        )
    return parsed


def _active(control: dict[str, Any]) -> bool:
    return not any(p.get("name") == "status" and p.get("value") == "withdrawn" for p in control.get("props", []))


def build_manifest(files: dict[str, bytes], analysis_rows: list[list[str]], *, previous: dict[str, Any]) -> dict:
    catalog = json.loads(files["catalog"])["catalog"]
    r2_ids = [str(row["id"]) for row in json.loads(CMMC_MANIFEST.read_text(encoding="utf-8"))["requirements"]]
    analysis = parse_analysis_rows(analysis_rows)

    predecessors: dict[str, list[dict[str, str]]] = {}
    not_carried: dict[str, str] = {}
    anomalies: list[dict[str, str]] = []
    for item in analysis:
        r2 = item["r2"]
        if r2 and r2 not in r2_ids:
            anomalies.append(
                {
                    "analysis_r2_id": r2,
                    "analysis_r3_id": item["r3"],
                    "note": f"{r2} is not a SP 800-171 Rev 2 identifier; the row is not used.",
                }
            )
            continue
        if not item["withdrawn"]:
            if r2:
                links = predecessors.setdefault(item["r3"], [])
                links.append({"id": r2, "relationship": "carried_forward", "change": item["change"]})
            continue
        text = item["withdrawn_text"]
        incorporated = re.match(r"^(?:Withdrawn\s+)?Incorporated into (.*)", text)
        if incorporated:
            for target in _R3_ID.findall(incorporated.group(1)):
                target = re.sub(r"(03\.\d{2})[ .]?(\d{2})", r"\1.\2", target)
                predecessors.setdefault(target, []).append(
                    {"id": r2, "relationship": "incorporated_into", "change": "withdrawn"}
                )
        else:
            not_carried[r2] = text.removeprefix("Withdrawn").strip()

    rows: list[dict[str, Any]] = []
    families: dict[str, dict[str, Any]] = {}
    for group in catalog["groups"]:
        family = str(group["id"]).removeprefix("SP_800_171_")
        risk, evidence = FAMILY_PROFILE[family]
        families[family] = {"title": group["title"], "risk_domain": risk}
        for control in group.get("controls", []):
            if not _active(control):
                continue
            requirement = str(control["id"]).removeprefix("SP_800_171_")
            rows.append(
                {
                    "id": requirement,
                    "title": control["title"],
                    "family": family,
                    "risk_domain": risk,
                    "required_evidence_types": list(evidence),
                    "r2_predecessors": sorted(
                        predecessors.get(requirement, []),
                        key=lambda link: [int(p) for p in link["id"].split(".")],
                    ),
                }
            )
    active = {row["id"] for row in rows}
    dangling = sorted(set(predecessors) - active)
    if dangling:
        raise SystemExit(f"analysis links Rev 2 requirements to non-active Rev 3 ids: {dangling}")
    accounted = {link["id"] for row in rows for link in row["r2_predecessors"]} | set(not_carried)
    if accounted != set(r2_ids):
        raise SystemExit(f"Rev 2 requirements not accounted for: {sorted(set(r2_ids) - accounted)}")

    return {
        "schema": "trustops.framework_pack_manifest.v1",
        "source": {
            "name": "NIST SP 800-171 Rev. 3, Protecting Controlled Unclassified Information in Nonfederal Systems",
            "version": "Revision 3 (May 2024)",
            "url": PUBLICATION_URL,
            "pdf": PDF_URL,
            "pdf_sha256": hashlib.sha256(files["pdf"]).hexdigest(),
            "oscal_repository": "https://github.com/usnistgov/oscal-content",
            "oscal_commit": OSCAL_COMMIT,
            "catalog_file": CATALOG_FILE,
            "catalog_version": catalog["metadata"].get("version"),
            "catalog_sha256": hashlib.sha256(files["catalog"]).hexdigest(),
            "r2_r3_analysis": {
                "name": "NIST SP 800-171 Rev. 2 to Rev. 3 change analysis",
                "url": ANALYSIS_URL,
                "sha256": hashlib.sha256(files["analysis"]).hexdigest(),
                "sheet": ANALYSIS_SHEET,
            },
            "pulled_at": previous.get("source", {}).get("pulled_at") or date.today().isoformat(),
            "note": (
                "NIST publications are U.S. Government works not subject to copyright in the United States. "
                "The manifest stores requirement identifiers and official short titles only."
            ),
        },
        "families": families,
        "rows": rows,
        "r2_not_carried": [
            {"id": r2, "reason": not_carried[r2]}
            for r2 in sorted(not_carried, key=lambda value: [int(p) for p in value.split(".")])
        ],
        "source_anomalies": anomalies,
        "unmapped": previous.get("unmapped", []),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source-dir", type=Path, help="read the three source files from this directory instead")
    args = parser.parse_args()
    files = {name: _fetch(name, args.source_dir) for name in FILES}
    analysis_rows = read_xlsx_rows(io.BytesIO(files["analysis"]))
    previous = json.loads(OUTPUT.read_text(encoding="utf-8")) if OUTPUT.is_file() else {}
    manifest = build_manifest(files, analysis_rows, previous=previous)
    OUTPUT.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}: {len(manifest['rows'])} active requirements")


if __name__ == "__main__":
    main()
