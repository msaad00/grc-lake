"""Deterministic, offline integrity gate for framework control/article IDs.

A typo'd or invented control_id or article_id must fail CI without any network
access. Three layers of defence:

  (a) every mapping ``article_id`` matches a per-framework FORMAT regex;
  (b) every mapping ``article_id`` is present in the committed
      ``frameworks/verified_article_ids.json`` allowlist for its framework —
      so a *new* mapping cannot ship until a human adds the verified id;
  (c) every catalog control maps to a ``framework_id`` that exists in the
      registry, and every control referenced in the mappings exists in the
      catalog (referential integrity).

The allowlist is seeded from the audit-verified ids currently used in
``mappings/control_articles.json``. Live source_sha256/pulled_at provenance is
deliberately out of scope here (HTML landing pages are not reproducible); that
is tracked as a separate follow-up.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

# Per-framework article_id FORMAT regexes. These describe the *shape* of a real
# identifier for each framework so an invented id (wrong prefix, wrong
# numbering) fails fast, before the allowlist check even runs.
_FORMAT_PATTERNS: dict[str, str] = {
    "soc2": r"^(CC\d|A\d|C\d|PI\d|P\d)",
    "iso-27001-2022": r"^A\.\d",
    "iso-27017-2015": r"^(CLD\.)?\d+(\.\d+)+$",
    "gdpr-2016-679": r"^Art\.\d+$",
    "nist-ai-rmf": r"^(GOVERN|MAP|MEASURE|MANAGE)-\d",
    "nist-csf-2.0": r"^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}$",
    "hipaa-security-rule": r"^164\.",
    "pci-dss-v4": r"^Req-\d",
    "eu-ai-act-2024-1689": r"^Art\.\d+$",
    "iso-42001-2023": r"^\d+(\.\d+)*$",
    "cis_aws": r"^\d+(\.\d+)*$",
    "cmmc-2-level2": r"^3\.\d+\.\d+$",
    "fedramp-moderate": r"^[A-Z]{2}-\d",
    "nist-800-53-rev5": r"^[A-Z]{2}-\d+(\.\d+)?$",
    "nist-rmf-800-37r2": r"^[PCSIARM]-\d+$",
    "cis-controls-v8.1": r"^Control-\d+$",
    "iso-27701-2025": r"^A\.[123]\.\d+(\.\d+)?$",
}

_FRAMEWORK_FAMILIES = {"assurance", "security", "privacy", "ai-governance", "cloud", "sector"}


def _load(rel: str) -> dict:
    return json.loads(Path(rel).read_text())


def _rows(mappings: dict) -> list[dict]:
    return mappings.get("mappings", mappings if isinstance(mappings, list) else [])


def _frameworks(registry: dict) -> list[dict]:
    return registry.get("frameworks", registry if isinstance(registry, list) else [])


def _controls(catalog: dict) -> list[dict]:
    return catalog.get("controls", catalog if isinstance(catalog, list) else [])


def test_every_framework_has_a_format_pattern() -> None:
    """Catch a new implemented framework that ships without a registered id format."""
    registry = _frameworks(_load("frameworks/registry.json"))
    implemented_ids = {
        fw["framework_id"] for fw in registry if str(fw.get("implementation_status") or "").startswith("implemented")
    }
    missing = sorted(implemented_ids - set(_FORMAT_PATTERNS))
    assert missing == [], f"framework(s) without an article_id format pattern: {missing}"


def test_mapping_article_ids_match_format_regex() -> None:
    offenders = []
    for row in _rows(_load("mappings/control_articles.json")):
        framework_id = row["framework_id"]
        pattern = _FORMAT_PATTERNS.get(framework_id)
        if pattern is None:
            offenders.append(f"{row['control_id']}: no format pattern for framework {framework_id}")
            continue
        for article in row.get("articles", []):
            article_id = article["article_id"]
            if not re.match(pattern, article_id):
                offenders.append(
                    f"{row['control_id']}: article_id {article_id!r} does not match {pattern} for {framework_id}"
                )
    assert offenders == [], offenders


def test_mapping_article_ids_are_in_verified_allowlist() -> None:
    allow = _load("frameworks/verified_article_ids.json")["framework_article_ids"]
    offenders = []
    for row in _rows(_load("mappings/control_articles.json")):
        framework_id = row["framework_id"]
        known = set(allow.get(framework_id, []))
        for article in row.get("articles", []):
            article_id = article["article_id"]
            if article_id not in known:
                offenders.append(
                    f"{row['control_id']}: article_id {article_id!r} not in verified_article_ids.json "
                    f"for {framework_id} — add it after verifying against the official source"
                )
    assert offenders == [], offenders


def test_verified_allowlist_only_lists_in_use_ids() -> None:
    """The allowlist must not drift from the mappings: every allowlisted id is
    actually used. (Combined with the in-allowlist check above, this pins the
    allowlist to exactly the set of ids in active mappings.)"""
    allow = _load("frameworks/verified_article_ids.json")["framework_article_ids"]
    in_use: dict[str, set[str]] = {}
    for row in _rows(_load("mappings/control_articles.json")):
        in_use.setdefault(row["framework_id"], set()).update(
            article["article_id"] for article in row.get("articles", [])
        )
    offenders = []
    for framework_id, ids in allow.items():
        stale = sorted(set(ids) - in_use.get(framework_id, set()))
        if stale:
            offenders.append(f"{framework_id}: allowlisted ids not used by any mapping: {stale}")
    assert offenders == [], offenders


def test_verified_allowlist_ids_also_match_format_regex() -> None:
    """Defence in depth: nothing malformed can be smuggled into the allowlist."""
    allow = _load("frameworks/verified_article_ids.json")["framework_article_ids"]
    offenders = []
    for framework_id, ids in allow.items():
        pattern = _FORMAT_PATTERNS.get(framework_id)
        if pattern is None:
            offenders.append(f"{framework_id}: allowlisted framework has no format pattern")
            continue
        for article_id in ids:
            if not re.match(pattern, article_id):
                offenders.append(f"{framework_id}: allowlisted id {article_id!r} does not match {pattern}")
    assert offenders == [], offenders


def test_catalog_controls_reference_registered_frameworks() -> None:
    registry_ids = {fw["framework_id"] for fw in _frameworks(_load("frameworks/registry.json"))}
    offenders = []
    for control in _controls(_load("controls/catalog.json")):
        framework_id = control["framework_id"]
        if framework_id not in registry_ids:
            offenders.append(f"{control['control_id']}: framework_id {framework_id!r} not in registry")
    assert offenders == [], offenders


def test_framework_registry_declares_a_display_family() -> None:
    registry = _frameworks(_load("frameworks/registry.json"))
    offenders = [
        f"{fw.get('framework_id')}: invalid family {fw.get('family')!r}"
        for fw in registry
        if fw.get("family") not in _FRAMEWORK_FAMILIES
    ]
    assert offenders == []


def test_mapping_controls_exist_in_catalog() -> None:
    catalog_ids = {control["control_id"] for control in _controls(_load("controls/catalog.json"))}
    offenders = []
    for row in _rows(_load("mappings/control_articles.json")):
        control_id = row["control_id"]
        if control_id not in catalog_ids:
            offenders.append(f"mapping references control {control_id!r} that is absent from catalog.json")
    assert offenders == [], offenders


def test_mapping_framework_matches_catalog_framework() -> None:
    """A mapping's framework_id must equal the catalog control's framework_id."""
    catalog = {c["control_id"]: c["framework_id"] for c in _controls(_load("controls/catalog.json"))}
    offenders = []
    for row in _rows(_load("mappings/control_articles.json")):
        control_id = row["control_id"]
        expected = catalog.get(control_id)
        if expected is not None and row["framework_id"] != expected:
            offenders.append(
                f"{control_id}: mapping framework {row['framework_id']!r} != catalog framework {expected!r}"
            )
    assert offenders == [], offenders
