"""Fill placeholder control titles from public-domain NIST catalogs.

58% of the control catalog carries titles that are an identifier plus
boilerplate — "FedRAMP Moderate IR-3 — assessed from cloud posture and audit
evidence". For those the catalog records *which* control exists, not what it
requires, so nothing can be mapped into a safeguard on evidence a reviewer can
check.

Two rules decide what this may touch, and they come from the registry's own
``copyright_guardrail`` fields rather than from convenience:

* **NIST SP 800-53, CSF, and AI RMF are public-domain U.S. government work.**
  Their control titles can be stored verbatim, and are checkable by anyone
  against the published catalog.
* **ISO text is licensed.** The registry says to keep identifiers and short
  internal titles only, so ISO frameworks are never enriched here. That is a
  legal boundary, not a gap to close later.

NIST CSF 2.0 is public domain but is *not* a usable source: its OSCAL catalog
titles each subcategory with its own identifier -- ``GV.OC-01`` is titled
"GV.OC-01" -- so importing it would fill 106 titles with no content. The guard
in :func:`enrich_catalog` rejects a title that merely repeats the id, because
coverage that looks enriched but says nothing is worse than an honest
placeholder. CSF text lives in the published framework document, not here.

Every enriched title records the source URL and the SHA-256 of the exact
document it came from, so provenance is verifiable rather than asserted.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from pathlib import Path
from typing import Any

from security_lakehouse.jsontypes import JsonObject

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CATALOG = ROOT / "controls" / "catalog.json"

# Frameworks whose source is public-domain U.S. government work, mapped to the
# OSCAL catalog that defines them and the prefix stripped from our control ids.
PUBLIC_DOMAIN_SOURCES: dict[str, dict[str, str]] = {
    "fedramp-moderate": {
        "url": (
            "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
            "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
        ),
        "prefix": "FEDRAMP-",
        "source_name": "NIST SP 800-53 Rev. 5",
    },
}

# Titles that are only an identifier plus a stock phrase.
PLACEHOLDER = re.compile(r"—\s*assessed from .*evidence\s*$", re.IGNORECASE)


def is_placeholder(title: str) -> bool:
    """True when a title names a control without saying what it requires."""
    return bool(PLACEHOLDER.search(title or ""))


def fetch(url: str, *, timeout: float = 180.0) -> tuple[bytes, str]:
    """Return the document and its SHA-256, so the import can be re-verified."""
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - fixed https NIST URL
        raw = response.read()
    return raw, hashlib.sha256(raw).hexdigest()


def oscal_titles(raw: bytes) -> dict[str, str]:
    """Flatten an OSCAL catalog into ``{CONTROL-ID: title}``, enhancements included."""
    catalog = json.loads(raw)["catalog"]
    out: dict[str, str] = {}

    def record(control: JsonObject) -> None:
        out[str(control["id"]).upper()] = str(control.get("title") or "")
        for nested in control.get("controls") or []:
            record(nested)

    def walk(groups: list[JsonObject] | None) -> None:
        for group in groups or []:
            for control in group.get("controls") or []:
                record(control)
            walk(group.get("groups"))

    walk(catalog.get("groups"))
    for control in catalog.get("controls") or []:
        record(control)
    return out


def enrich_catalog(
    catalog_path: str | Path | None = None,
    *,
    titles_by_framework: dict[str, tuple[dict[str, str], str, str]],
    apply: bool,
) -> dict[str, Any]:
    """Fill placeholder titles for the given frameworks.

    ``titles_by_framework`` maps a framework id to its
    ``(titles, source_url, source_sha256)``. Returns a report; writes only when
    ``apply`` is set, so a dry run can be diffed first.
    """
    path = Path(catalog_path or DEFAULT_CATALOG)
    payload = json.loads(path.read_text(encoding="utf-8"))

    filled = 0
    unresolved: list[str] = []
    for control in payload["controls"]:
        framework = control.get("framework_id")
        if framework not in titles_by_framework or not is_placeholder(control.get("title", "")):
            continue
        titles, url, digest = titles_by_framework[framework]
        prefix = PUBLIC_DOMAIN_SOURCES[framework]["prefix"]
        key = str(control["control_id"]).replace(prefix, "").upper()
        official = titles.get(key)
        # A "title" that just repeats the identifier carries no content. NIST's
        # CSF OSCAL does this for subcategories -- GV.OC-01 is titled "GV.OC-01"
        # -- and accepting it would look like enrichment while adding nothing,
        # inflating coverage with requirements still nobody can curate.
        if not official or official.strip().upper() == key:
            unresolved.append(str(control["control_id"]))
            continue
        source_name = PUBLIC_DOMAIN_SOURCES[framework]["source_name"]
        control["title"] = f"{key} — {official}"
        control["title_source_url"] = url
        control["title_source_sha256"] = digest
        control["title_source_name"] = source_name
        filled += 1

    if apply and filled:
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    return {"filled": filled, "unresolved": unresolved, "applied": bool(apply and filled)}
