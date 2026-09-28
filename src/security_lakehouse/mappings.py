"""Reviewed control_id ↔ source_article mappings.

Replaces the heuristic crosswalk with auditor-reviewed mappings. Each
mapping points from a local control_id to one or more articles in the
framework's official source, with reviewer attestation and rationale.

Loaded from ``mappings/control_articles.json``; readonly + validated.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from security_lakehouse.catalog import _data_root, load_control_catalog

ROOT = _data_root()
DEFAULT_MAPPINGS = ROOT / "mappings" / "control_articles.json"
DEFAULT_EQUIVALENCE = ROOT / "mappings" / "framework_equivalence.json"


def load_control_article_mappings(
    path: str | Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Return a {control_id: mapping_record} dict."""
    payload = json.loads(Path(path or DEFAULT_MAPPINGS).read_text(encoding="utf-8"))
    mappings = payload.get("mappings")
    if not isinstance(mappings, list):
        raise ValueError("control article mappings must contain a `mappings` list")
    out: dict[str, dict[str, Any]] = {}
    for mapping in mappings:
        cid = str(mapping.get("control_id") or "")
        if not cid:
            continue
        out[cid] = mapping
    return out


def article_mapping_reviewed(mapping: dict[str, Any] | None) -> bool:
    """A control->article mapping counts as reviewed only if it has articles and none is ``proposed``.

    This is the catalog's source-citation review, separate from safeguard
    mapping review (see :func:`security_lakehouse.safeguards.effective_review_state`).
    """
    if not mapping:
        return False
    articles = mapping.get("articles") or []
    return bool(articles) and all(str(a.get("review_status") or "reviewed") != "proposed" for a in articles)


def validate_control_article_mappings(
    path: str | Path | None = None,
) -> list[str]:
    """Return errors for missing/invalid mapping fields."""
    errors: list[str] = []
    mappings = load_control_article_mappings(path)
    for cid, mapping in mappings.items():
        if not mapping.get("framework_id"):
            errors.append(f"mapping {cid} missing framework_id")
        articles = mapping.get("articles") or []
        if not articles:
            errors.append(f"mapping {cid} has no articles")
        for article in articles:
            for required in ("article_id", "title", "official_source_url", "reviewed_by", "reviewed_at", "rationale"):
                if not str(article.get(required) or "").strip():
                    errors.append(f"mapping {cid} article missing {required}")
    return errors


def build_reviewed_crosswalk(
    mappings_path: str | Path | None = None,
    catalog_path: str | Path | None = None,
) -> dict[str, Any]:
    """Compute a reviewed framework × framework crosswalk.

    The matrix cells list:
      * ``shared_domains``: ``risk_domain`` values both frameworks cover. This
        is the load-bearing cross-framework signal — article_id and control_id
        are framework-unique, so they only ever match on the diagonal, whereas
        ``risk_domain`` is the shared semantic axis that makes "answer once,
        satisfy many" visible (e.g. access-control coverage in SOC 2 and ISO).
      * ``shared_articles``: same article_id appearing in both frameworks'
        mapping tables (rare across frameworks, but supported).
      * ``shared_controls``: same control_id touching both frameworks
        (this matters if a control maps into multiple framework versions).
      * ``mapping_count`` / ``article_count`` / ``domain_count`` totals on the
        row header.
    """
    mappings = load_control_article_mappings(mappings_path)
    catalog = load_control_catalog(catalog_path)
    by_framework: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for cid, mapping in mappings.items():
        framework_id = str(mapping.get("framework_id") or "")
        if framework_id:
            by_framework[framework_id][cid] = mapping

    def domains_for(framework: str) -> set[str]:
        return {
            str(catalog[cid].get("risk_domain") or "")
            for cid in by_framework[framework]
            if cid in catalog and str(catalog[cid].get("risk_domain") or "")
        }

    frameworks = sorted(by_framework)
    matrix: list[dict[str, Any]] = []
    for left in frameworks:
        left_articles = {
            article["article_id"]
            for mapping in by_framework[left].values()
            for article in (mapping.get("articles") or [])
        }
        left_controls = set(by_framework[left])
        left_domains = domains_for(left)
        row: dict[str, Any] = {
            "framework_id": left,
            "mapping_count": len(by_framework[left]),
            "article_count": len(left_articles),
            "domain_count": len(left_domains),
            "cells": [],
        }
        for right in frameworks:
            right_articles = {
                article["article_id"]
                for mapping in by_framework[right].values()
                for article in (mapping.get("articles") or [])
            }
            right_controls = set(by_framework[right])
            right_domains = domains_for(right)
            row["cells"].append(
                {
                    "framework_id": right,
                    "is_self": left == right,
                    "shared_domains": sorted(left_domains & right_domains),
                    "shared_articles": sorted(left_articles & right_articles),
                    "shared_controls": sorted(left_controls & right_controls),
                }
            )
        matrix.append(row)
    return {"frameworks": frameworks, "matrix": matrix}


def load_framework_equivalence(
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Return the framework equivalence payload (groups of related controls)."""
    payload = json.loads(Path(path or DEFAULT_EQUIVALENCE).read_text(encoding="utf-8"))
    groups = payload.get("groups")
    if not isinstance(groups, list):
        raise ValueError("framework equivalence must contain a `groups` list")
    return payload


def validate_framework_equivalence(
    path: str | Path | None = None,
    catalog_path: str | Path | None = None,
) -> list[str]:
    """Return validation errors for equivalence groups."""
    errors: list[str] = []
    payload = load_framework_equivalence(path)
    catalog = load_control_catalog(catalog_path)
    for group in payload.get("groups", []):
        group_id = str(group.get("group_id") or "")
        if not group_id:
            errors.append("equivalence group missing group_id")
            continue
        controls = group.get("controls") or []
        if len(controls) < 2:
            errors.append(f"group {group_id} needs at least two controls")
        for entry in controls:
            cid = str(entry.get("control_id") or "")
            if not cid:
                errors.append(f"group {group_id} has empty control_id")
                continue
            if cid not in catalog:
                errors.append(f"group {group_id} references unknown control {cid}")
            fw = str(entry.get("framework_id") or "")
            if fw and catalog.get(cid, {}).get("framework_id") != fw:
                errors.append(f"group {group_id} framework_id mismatch for {cid}")
        for required in ("label", "risk_domain", "rationale", "reviewed_by", "reviewed_at"):
            if not str(group.get(required) or "").strip():
                errors.append(f"group {group_id} missing {required}")
    return errors


def build_equivalence_index(
    path: str | Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Map each control_id to its equivalence group and sibling controls."""
    payload = load_framework_equivalence(path)
    index: dict[str, dict[str, Any]] = {}
    for group in payload.get("groups", []):
        group_id = str(group["group_id"])
        controls = group.get("controls") or []
        control_ids = [str(c["control_id"]) for c in controls if c.get("control_id")]
        for entry in controls:
            cid = str(entry.get("control_id") or "")
            if not cid:
                continue
            siblings = [other for other in control_ids if other != cid]
            existing = index.get(cid)
            if existing and existing["group_id"] != group_id:
                merged = sorted(set(existing["equivalent_controls"]) | set(siblings))
                existing["equivalent_controls"] = merged
                existing["group_controls"] = sorted(set(existing["group_controls"]) | set(control_ids))
                existing.setdefault("also_in_groups", []).append(group_id)
                continue
            index[cid] = {
                "group_id": group_id,
                "label": group.get("label"),
                "risk_domain": group.get("risk_domain"),
                "role": entry.get("role", "equivalent"),
                "equivalent_controls": siblings,
                "group_controls": control_ids,
            }
    return index


def build_framework_equivalence(
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Return equivalence groups plus a lookup index for API consumers."""
    payload = load_framework_equivalence(path)
    return {
        "schema": payload.get("schema"),
        "group_count": len(payload.get("groups", [])),
        "groups": payload.get("groups", []),
        "index": build_equivalence_index(path),
    }
