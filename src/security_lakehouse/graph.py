"""Build a framework → control → evidence → asset graph from the lake.

The graph is the single source of truth the React /graph canvas renders.
Every node carries its kind so the canvas can shape and colour them, and
every edge carries the relationship name so the canvas can filter.

Node kinds:
    framework, control, evidence_type, asset

Edge kinds:
    framework_has_control, control_requires_evidence, evidence_covers_asset
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from security_lakehouse.catalog import load_control_catalog, load_framework_registry
from security_lakehouse.framework_provenance import framework_pack_state
from security_lakehouse.generations import generation_reader
from security_lakehouse.io import read_jsonl


def _escape_id_segment(value: str) -> str:
    """Escape a free-text segment so it can't collide across node id namespaces.

    Node ids join a kind prefix and a variable segment with ``:`` (e.g.
    ``evidence:{event_type}``, ``asset:{asset_id}``). A raw value that itself
    contains ``:`` could otherwise produce an id that collides with a value
    from another namespace. Escaping the backslash first, then the delimiter,
    keeps the mapping injective while leaving delimiter-free values untouched
    (so ids are byte-identical to the pre-hardening output for normal inputs).
    """
    return value.replace("\\", "\\\\").replace(":", "\\:")


def _gold_asset_rows(lake_dir: Path) -> list[dict[str, Any]]:
    path = lake_dir / "gold" / "asset_risk.jsonl"
    return read_jsonl(path) if path.is_file() else []


def _silver_event_rows(lake_dir: Path) -> list[dict[str, Any]]:
    path = lake_dir / "silver" / "normalized_events.jsonl"
    return read_jsonl(path) if path.is_file() else []


def _bronze_raw_rows(lake_dir: Path) -> list[dict[str, Any]]:
    path = lake_dir / "bronze" / "raw_events.jsonl"
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for row in read_jsonl(path):
        raw = row.get("raw")
        if isinstance(raw, dict):
            rows.append(raw)
    return rows


def _freshness_index(lake: Path) -> dict[str, dict[str, Any]]:
    """Map evidence_id / event_id to gold freshness rows for graph enrichment."""
    path = lake / "gold" / "evidence_freshness.jsonl"
    if not path.is_file():
        return {}
    index: dict[str, dict[str, Any]] = {}
    for row in read_jsonl(path):
        for key in (row.get("evidence_id"), row.get("event_id")):
            if key:
                index[str(key)] = row
    return index


@generation_reader
def build_compliance_graph(lake_dir: str | Path) -> dict[str, Any]:
    """Return a serialisable graph spanning frameworks → controls → evidence → assets."""
    lake = Path(lake_dir)
    frameworks = load_framework_registry()
    controls = load_control_catalog()
    events = _silver_event_rows(lake)
    assets = _gold_asset_rows(lake)

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    # Single membership index updated as nodes are appended, so control→evidence
    # edge wiring stays O(1) instead of rederiving the id set per control.
    existing_ids: set[str] = set()

    def _add_node(node: dict[str, Any]) -> None:
        nodes.append(node)
        existing_ids.add(node["id"])

    # Framework nodes: only packs with seeded controls. A planned or
    # superseded registry stub would be an isolated node with no path.
    seeded_frameworks = {str(control.get("framework_id") or "") for control in controls.values()}
    for framework_id, framework in frameworks.items():
        if framework_pack_state(framework, int(framework_id in seeded_frameworks)) != "seeded":
            continue
        _add_node(
            {
                "id": f"framework:{framework_id}",
                "kind": "framework",
                "label": framework.get("name", framework_id),
                "subtitle": framework.get("version"),
                "framework_id": framework_id,
            }
        )

    # Control nodes + framework→control edges
    for control_id, control in controls.items():
        framework_id = control.get("framework_id") or ""
        _add_node(
            {
                "id": f"control:{control_id}",
                "kind": "control",
                "label": control_id,
                "subtitle": control.get("title"),
                "framework_id": framework_id,
                "owner": control.get("owner"),
            }
        )
        if framework_id:
            edges.append(
                {
                    "id": f"e:f{framework_id}-c{control_id}",
                    "source": f"framework:{framework_id}",
                    "target": f"control:{control_id}",
                    "kind": "framework_has_control",
                }
            )

    # Evidence-type nodes + control→evidence edges (deduped by event_type)
    evidence_count_by_type: Counter[str] = Counter()
    type_to_controls: dict[str, set[str]] = {}
    type_to_assets: dict[str, set[str]] = {}
    for event in events:
        event_type = str(event.get("event_type") or "unknown")
        evidence_count_by_type[event_type] += 1
        controls_for = type_to_controls.setdefault(event_type, set())
        assets_for = type_to_assets.setdefault(event_type, set())
        for cid in event.get("control_ids") or []:
            controls_for.add(str(cid))
        if asset_id := event.get("asset_id"):
            assets_for.add(str(asset_id))

    for event_type, count in evidence_count_by_type.items():
        node_id = f"evidence:{_escape_id_segment(event_type)}"
        _add_node(
            {
                "id": node_id,
                "kind": "evidence_type",
                "label": event_type,
                "subtitle": f"{count} records",
                "event_count": count,
            }
        )
        for cid in type_to_controls.get(event_type, set()):
            if f"control:{cid}" not in existing_ids:
                continue
            edges.append(
                {
                    "id": f"e:c{cid}-t{event_type}",
                    "source": f"control:{cid}",
                    "target": node_id,
                    "kind": "control_requires_evidence",
                }
            )

    # Asset nodes + evidence→asset edges
    asset_rows = {str(row.get("asset_id") or ""): row for row in assets}
    seen_assets: set[str] = set()
    for event_type, asset_ids in type_to_assets.items():
        for asset_id in asset_ids:
            if not asset_id:
                continue
            asset_node_id = f"asset:{_escape_id_segment(asset_id)}"
            evidence_node_id = f"evidence:{_escape_id_segment(event_type)}"
            if asset_id not in seen_assets:
                seen_assets.add(asset_id)
                row = asset_rows.get(asset_id, {})
                _add_node(
                    {
                        "id": asset_node_id,
                        "kind": "asset",
                        "label": row.get("asset_name") or asset_id,
                        "asset_id": asset_id,
                        "subtitle": row.get("asset_type") or "asset",
                        "owner": row.get("asset_owner"),
                        "environment": row.get("environment"),
                        "risk_score": row.get("risk_score"),
                    }
                )
            edges.append(
                {
                    "id": f"e:t{event_type}-a{asset_id}",
                    "source": evidence_node_id,
                    "target": asset_node_id,
                    "kind": "evidence_covers_asset",
                }
            )

    counts = {
        "framework": sum(1 for n in nodes if n["kind"] == "framework"),
        "control": sum(1 for n in nodes if n["kind"] == "control"),
        "evidence_type": sum(1 for n in nodes if n["kind"] == "evidence_type"),
        "asset": sum(1 for n in nodes if n["kind"] == "asset"),
    }
    return {"nodes": nodes, "edges": edges, "counts": counts}


@generation_reader
def analyze_coverage(lake_dir: str | Path, graph: dict[str, Any] | None = None) -> dict[str, Any]:
    """Compute compliance coverage and gaps over the directed compliance graph.

    This is the honest, data-backed version of "reachability" for *this* graph:
    it follows the directed chain ``framework -> control -> evidence -> asset``
    and reports which assets are reached by control evidence, which controls have
    no evidence at all, and which frameworks have no covered control. It is *not*
    infra attack-path reachability -- there is no exposure/network data modeled
    here -- it is compliance coverage and gap analysis.

    Reuses :func:`build_compliance_graph` (pass ``graph`` to avoid rebuilding).
    Returns a JSON-able dict with ``summary``, ``assets``, and ``orphans``.
    """
    if graph is None:
        graph = build_compliance_graph(lake_dir)
    nodes = list(graph["nodes"])
    edges = graph["edges"]

    nodes_by_id = {node["id"]: node for node in nodes}

    # The graph builder only mints asset nodes from evidence events, so an asset
    # that ships in the gold asset table with *no* evidence edge would otherwise
    # be invisible -- yet that is exactly the gap an auditor cares about. Fold in
    # those evidence-less assets as nodes so they surface as uncovered/orphan.
    for row in _gold_asset_rows(Path(lake_dir)):
        asset_id = str(row.get("asset_id") or "")
        if not asset_id:
            continue
        node_id = f"asset:{_escape_id_segment(asset_id)}"
        if node_id in nodes_by_id:
            continue
        ghost = {
            "id": node_id,
            "kind": "asset",
            "label": row.get("asset_name") or asset_id,
            "asset_id": asset_id,
            "subtitle": row.get("asset_type") or "asset",
            "owner": row.get("asset_owner"),
            "environment": row.get("environment"),
            "risk_score": row.get("risk_score"),
        }
        nodes.append(ghost)
        nodes_by_id[node_id] = ghost

    # Directed adjacency for the three compliance edge kinds.
    framework_to_controls: dict[str, set[str]] = {}
    control_to_evidence: dict[str, set[str]] = {}
    evidence_to_assets: dict[str, set[str]] = {}
    for edge in edges:
        kind = edge["kind"]
        source = edge["source"]
        target = edge["target"]
        if kind == "framework_has_control":
            framework_to_controls.setdefault(source, set()).add(target)
        elif kind == "control_requires_evidence":
            control_to_evidence.setdefault(source, set()).add(target)
        elif kind == "evidence_covers_asset":
            evidence_to_assets.setdefault(source, set()).add(target)

    control_ids = [node["id"] for node in nodes if node["kind"] == "control"]
    framework_ids = [node["id"] for node in nodes if node["kind"] == "framework"]
    asset_ids = [node["id"] for node in nodes if node["kind"] == "asset"]

    # Controls with at least one evidence edge are "covered" controls.
    covered_control_ids = {cid for cid in control_ids if control_to_evidence.get(cid)}

    # Per-asset coverage: walk control -> evidence -> asset to attribute each
    # asset to the controls (and their frameworks) whose evidence reaches it.
    control_to_framework = {
        node["id"]: f"framework:{node.get('framework_id')}" for node in nodes if node["kind"] == "control"
    }
    asset_to_controls: dict[str, set[str]] = {aid: set() for aid in asset_ids}
    asset_to_frameworks: dict[str, set[str]] = {aid: set() for aid in asset_ids}
    for control_id in covered_control_ids:
        framework_id = control_to_framework.get(control_id)
        for evidence_id in control_to_evidence.get(control_id, set()):
            for asset_id in evidence_to_assets.get(evidence_id, set()):
                asset_to_controls.setdefault(asset_id, set()).add(control_id)
                if framework_id and framework_id in nodes_by_id:
                    asset_to_frameworks.setdefault(asset_id, set()).add(framework_id)

    def _label(node_id: str) -> str:
        node = nodes_by_id.get(node_id)
        return str(node["label"]) if node else node_id

    assets_report: list[dict[str, Any]] = []
    covered_assets = 0
    for asset_id in sorted(asset_ids):
        controls_for = sorted(asset_to_controls.get(asset_id, set()))
        frameworks_for = sorted(asset_to_frameworks.get(asset_id, set()))
        is_covered = bool(controls_for)
        if is_covered:
            covered_assets += 1
        node = nodes_by_id.get(asset_id, {})
        assets_report.append(
            {
                "asset_id": asset_id,
                "label": _label(asset_id),
                "asset_type": node.get("subtitle"),
                "owner": node.get("owner"),
                "environment": node.get("environment"),
                "covered": is_covered,
                "is_gap": not is_covered,
                "controls": [{"id": cid, "label": _label(cid)} for cid in controls_for],
                "frameworks": [{"id": fid, "label": _label(fid)} for fid in frameworks_for],
            }
        )

    # Orphans: controls with no evidence; frameworks with no covered control;
    # assets with no evidence reaching them.
    orphan_controls = sorted(cid for cid in control_ids if cid not in covered_control_ids)
    orphan_frameworks = sorted(
        fid for fid in framework_ids if not (framework_to_controls.get(fid, set()) & covered_control_ids)
    )
    orphan_assets = sorted(aid for aid in asset_ids if not asset_to_controls.get(aid))

    def _node_brief(node_id: str) -> dict[str, Any]:
        node = nodes_by_id.get(node_id, {})
        return {"id": node_id, "label": str(node.get("label") or node_id)}

    total_assets = len(asset_ids)
    uncovered_assets = total_assets - covered_assets
    coverage_pct = round(100.0 * covered_assets / total_assets, 2) if total_assets else 0.0

    summary = {
        "total_frameworks": len(framework_ids),
        "total_controls": len(control_ids),
        "covered_controls": len(covered_control_ids),
        "orphan_controls": len(orphan_controls),
        "total_assets": total_assets,
        "covered_assets": covered_assets,
        "uncovered_assets": uncovered_assets,
        "orphan_frameworks": len(orphan_frameworks),
        "coverage_pct": coverage_pct,
    }

    return {
        "summary": summary,
        "assets": assets_report,
        "orphans": {
            "controls": [_node_brief(cid) for cid in orphan_controls],
            "frameworks": [_node_brief(fid) for fid in orphan_frameworks],
            "assets": [_node_brief(aid) for aid in orphan_assets],
        },
    }


@generation_reader
def build_repository_graph(lake_dir: str | Path) -> dict[str, Any]:
    """Return a graph of repository topology + governance evidence.

    The source is the immutable bronze replay stream so the graph can preserve
    fields that the generic silver model intentionally flattens away. Public
    repo audit events and authenticated governance events share this model.
    """
    lake = Path(lake_dir)
    events = [
        row
        for row in _bronze_raw_rows(lake)
        if str(row.get("event_type") or "").startswith("repository.")
        or str((row.get("entity") or {}).get("asset_type") or "") == "repository"
    ]
    freshness_index = _freshness_index(lake)
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}

    def add_node(node_id: str, kind: str, label: str, **extra: Any) -> None:
        current = nodes.get(node_id, {})
        nodes[node_id] = {
            "id": node_id,
            "kind": kind,
            "label": label,
            **current,
            **{k: v for k, v in extra.items() if v is not None},
        }

    def add_edge(source: str, target: str, kind: str) -> None:
        edge_id = f"e:{source}->{target}:{kind}"
        edges[edge_id] = {"id": edge_id, "source": source, "target": target, "kind": kind}

    for event in events:
        entity = event.get("entity") or {}
        attributes = event.get("attributes") or {}
        repo_id = str(entity.get("asset_id") or attributes.get("repo_asset_id") or "repository:unknown")
        repo_label = str(entity.get("repo") or repo_id.split(":", 2)[-1] if ":" in repo_id else repo_id)
        add_node(
            repo_id,
            "repository",
            repo_label,
            subtitle=str(entity.get("asset_owner") or entity.get("owner") or "repository"),
            owner=entity.get("asset_owner") or entity.get("owner"),
            environment=entity.get("environment"),
            provider=entity.get("provider") or attributes.get("source_health", {}).get("provider"),
        )

        event_type = str(event.get("event_type") or "repository.unknown")
        evidence = event.get("evidence") or {}
        evidence_id = str(evidence.get("evidence_id") or event.get("event_id") or f"{repo_id}:{event_type}")
        evidence_node = f"evidence:{evidence_id}"
        freshness = freshness_index.get(evidence_id) or freshness_index.get(str(event.get("event_id") or ""))
        evidence_extra: dict[str, Any] = {
            "event_count": 1,
            "evidence_id": evidence.get("evidence_id") or evidence_id,
            "evidence_ref": evidence.get("evidence_ref"),
            "control_ids": [str(c) for c in event.get("controls") or []],
            "event_type": event_type,
        }
        if severity := event.get("severity"):
            evidence_extra["severity"] = str(severity)
        if freshness:
            evidence_extra["freshness_status"] = str(freshness.get("status") or "")
            if freshness.get("age_minutes") is not None:
                evidence_extra["freshness_age_minutes"] = int(freshness["age_minutes"])
        add_node(
            evidence_node,
            "evidence",
            event_type.replace("repository.", ""),
            subtitle=str(event.get("status") or "observed"),
            **evidence_extra,
        )
        add_edge(repo_id, evidence_node, "has_evidence")

        for control_id in event.get("controls") or []:
            control_node = f"control:{control_id}"
            add_node(control_node, "control", str(control_id), framework_id=_framework_from_control(str(control_id)))
            add_edge(evidence_node, control_node, "evidence_maps_control")

        if event_type == "repository.code_graph":
            _add_embedded_code_graph(repo_id, attributes, add_node, add_edge)
        elif event_type == "repository.authenticated_signal_gap":
            gap_node = f"{repo_id}:signal_gap:not_available_public_mode"
            add_node(
                gap_node,
                "signal_gap",
                "not_available_public_mode",
                subtitle="Private repository settings require an authenticated connector",
            )
            add_edge(repo_id, gap_node, "has_signal_gap")
            for signal in attributes.get("requires_authenticated_connector") or []:
                signal_node = f"{gap_node}:{signal}"
                add_node(signal_node, "governance_signal", str(signal), subtitle="not available in public mode")
                add_edge(gap_node, signal_node, "requires_authenticated_connector")
        elif event_type.startswith("repository.governance."):
            _add_governance_signal(repo_id, event_type, attributes, add_node, add_edge)
        else:
            _add_repository_signal_paths(repo_id, event_type, attributes, add_node, add_edge)

    counts = Counter(str(node["kind"]) for node in nodes.values())
    return {
        "nodes": sorted(nodes.values(), key=lambda node: (str(node["kind"]), str(node["id"]))),
        "edges": sorted(edges.values(), key=lambda edge: str(edge["id"])),
        "counts": dict(sorted(counts.items())),
    }


def _add_embedded_code_graph(repo_id: str, attributes: dict[str, Any], add_node: Any, add_edge: Any) -> None:
    kind_map = {
        "repository": "repository",
        "directory": "directory",
        "language": "language",
        "evidence_signal": "evidence_signal",
    }
    for node in attributes.get("nodes") or []:
        if not isinstance(node, dict):
            continue
        node_id = str(node.get("id") or "")
        if not node_id:
            continue
        add_node(
            node_id,
            kind_map.get(str(node.get("kind") or ""), str(node.get("kind") or "repo_node")),
            str(node.get("label") or node_id),
            subtitle=str(node.get("visibility") or node.get("path_count") or node.get("bytes") or ""),
            path_count=node.get("path_count"),
        )
    for edge in attributes.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        source = str(edge.get("source") or "")
        target = str(edge.get("target") or "")
        if source and target:
            add_edge(source, target, str(edge.get("kind") or "related"))
    for signal, value in (attributes.get("counts") or {}).items():
        if signal == "signals" and value == 0:
            no_signal = f"{repo_id}:signal_gap:no_public_signals"
            add_node(
                no_signal, "signal_gap", "no_public_signals", subtitle="No public repo evidence signals were detected"
            )
            add_edge(repo_id, no_signal, "has_signal_gap")


def _add_repository_signal_paths(
    repo_id: str, event_type: str, attributes: dict[str, Any], add_node: Any, add_edge: Any
) -> None:
    signal = event_type.removeprefix("repository.")
    signal_node = f"{repo_id}:signal:{signal}"
    add_node(signal_node, "evidence_signal", signal, subtitle=f"{attributes.get('path_count', 0)} paths")
    add_edge(repo_id, signal_node, "has_signal")
    path_kind = {
        "ci_workflow": "workflow",
        "dependency_manifest": "dependency_manifest",
        "codeowners": "ownership_file",
        "security_policy": "security_file",
    }.get(signal, "file")
    for path in attributes.get("paths") or []:
        path_node = f"{repo_id}:path:{path}"
        add_node(path_node, path_kind, str(path), subtitle=signal)
        add_edge(signal_node, path_node, "references_path")


def _add_governance_signal(
    repo_id: str, event_type: str, attributes: dict[str, Any], add_node: Any, add_edge: Any
) -> None:
    signal = event_type.removeprefix("repository.governance.")
    governance = attributes.get("governance") or {}
    available = governance.get("available")
    signal_node = f"{repo_id}:governance:{signal}"
    add_node(
        signal_node,
        "governance_signal",
        signal,
        subtitle="available" if available is not False else "not available",
    )
    add_edge(repo_id, signal_node, "has_governance_signal")
    if available is False:
        gap_node = f"{signal_node}:not_available_public_mode"
        add_node(gap_node, "signal_gap", "not_available_public_mode", subtitle=governance.get("reason"))
        add_edge(signal_node, gap_node, "requires_authenticated_connector")
        return
    if signal in {"collaborators", "teams"}:
        for item in governance.get("items") or []:
            if not isinstance(item, dict):
                continue
            label = str(item.get("login") or item.get("name") or "unknown")
            principal_node = f"{repo_id}:{signal}:{label}"
            add_node(
                principal_node,
                "principal" if signal == "collaborators" else "team",
                label,
                subtitle=str(item.get("role_name") or item.get("permission") or signal),
            )
            add_edge(signal_node, principal_node, f"has_{signal}")
    elif signal == "branch_protection":
        reviews = governance.get("required_pull_request_reviews") or {}
        checks = governance.get("required_status_checks") or {}
        if reviews:
            review_node = f"{signal_node}:reviews"
            add_node(
                review_node,
                "review_rule",
                "required reviews",
                subtitle=f"{reviews.get('required_approving_review_count', 0)} approvals",
            )
            add_edge(signal_node, review_node, "enforces")
        for check in checks.get("contexts") or []:
            check_node = f"{signal_node}:check:{check}"
            add_node(check_node, "status_check", str(check), subtitle="required status check")
            add_edge(signal_node, check_node, "requires_status_check")
    elif signal == "workflow_permissions":
        permission = governance.get("default_workflow_permissions")
        if permission:
            perm_node = f"{signal_node}:permission:{permission}"
            add_node(perm_node, "workflow_permission", str(permission), subtitle="default workflow permission")
            add_edge(signal_node, perm_node, "sets_permission")


def _framework_from_control(control_id: str) -> str | None:
    """Resolve framework_id from control_id prefix conventions."""
    prefixes = (
        ("SOC2-", "soc2"),
        ("ISO27001-", "iso-27001-2022"),
        ("ISO27017-", "iso-27017-2015"),
        ("ISO42001-", "iso-42001-2023"),
        ("PCI-DSS-", "pci-dss-v4"),
        ("NIST-AI-RMF-", "nist-ai-rmf"),
        ("NIST-CSF-", "nist-csf-2.0"),
        ("NIST-800-53-", "nist-800-53-rev5"),
        ("NIST-RMF-", "nist-rmf-800-37r2"),
        ("FEDRAMP-", "fedramp-moderate"),
        ("CIS-AWS-", "cis_aws"),
        ("CIS-CONTROLS-", "cis-controls-v8.1"),
        ("ISO27701-", "iso-27701-2025"),
        ("CMMC-", "cmmc-2-level2"),
        ("GDPR-", "gdpr-2016-679"),
        ("EU-AI-ACT-", "eu-ai-act-2024-1689"),
        ("HIPAA-", "hipaa-security-rule"),
    )
    for prefix, framework_id in prefixes:
        if control_id.startswith(prefix):
            return framework_id
    return None


def build_framework_crosswalk(controls_path: str | Path | None = None) -> dict[str, Any]:
    """Compute a heuristic framework × framework matrix of shared risk domains.

    Prefer :func:`security_lakehouse.mappings.build_reviewed_crosswalk` for
    auditor-reviewed mappings and
    :func:`security_lakehouse.mappings.build_framework_equivalence` for curated
    control-equivalence groups (managed GRC-style answer-once mapping).
    """
    controls = load_control_catalog(controls_path)
    by_framework: dict[str, list[dict[str, Any]]] = {}
    for control in controls.values():
        framework_id = str(control.get("framework_id") or "")
        by_framework.setdefault(framework_id, []).append(control)

    framework_ids = sorted(by_framework)
    matrix: list[dict[str, Any]] = []
    for left in framework_ids:
        row: dict[str, Any] = {"framework_id": left, "cells": []}
        for right in framework_ids:
            shared_domains = sorted(
                {c.get("risk_domain") for c in by_framework[left] if c.get("risk_domain")}
                & {c.get("risk_domain") for c in by_framework[right] if c.get("risk_domain")}
            )
            shared_owners = sorted(
                {c.get("owner") for c in by_framework[left] if c.get("owner")}
                & {c.get("owner") for c in by_framework[right] if c.get("owner")}
            )
            row["cells"].append(
                {
                    "framework_id": right,
                    "shared_risk_domains": shared_domains,
                    "shared_owners": shared_owners,
                    "is_self": left == right,
                }
            )
        matrix.append(row)
    return {"frameworks": framework_ids, "matrix": matrix}
