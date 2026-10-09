"""Bounded, local-first AI bill of materials import and export.

The canonical store intentionally keeps only portable inventory fields. Source
documents remain customer-controlled; GRC Lake does not upload or enrich them.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.io import read_json, write_json

STORE_RELATIVE_PATH = Path("aibom/inventory.json")
MAX_DOCUMENT_BYTES = 10 * 1024 * 1024
SUPPORTED_EXPORTS = ("cyclonedx-1.7", "spdx-3.0.1")


def _text(value: Any, *, limit: int = 4096) -> str:
    return str(value or "").strip()[:limit]


def _licenses(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    found: list[str] = []
    for item in value:
        if isinstance(item, str):
            license_id = item
        elif isinstance(item, dict):
            node = item.get("license")
            if not isinstance(node, dict):
                node = item
            license_id = node.get("id") or node.get("name") or ""
        else:
            continue
        text = _text(license_id, limit=256)
        if text and text not in found:
            found.append(text)
    return found


def _cyclonedx_items(document: dict[str, Any]) -> list[dict[str, Any]]:
    if document.get("bomFormat") != "CycloneDX":
        raise ValueError("expected a CycloneDX JSON document")
    version = _text(document.get("specVersion"), limit=16)
    if version not in {"1.5", "1.6", "1.7"}:
        raise ValueError("supported CycloneDX specVersion values are 1.5, 1.6, and 1.7")
    components = document.get("components") or []
    if not isinstance(components, list):
        raise ValueError("CycloneDX components must be an array")
    rows: list[dict[str, Any]] = []
    for component in components:
        if not isinstance(component, dict):
            continue
        component_type = _text(component.get("type"), limit=64)
        if component_type not in {"machine-learning-model", "data", "application", "library"}:
            continue
        name = _text(component.get("name"), limit=1024)
        if not name:
            continue
        external_refs = component.get("externalReferences") or []
        has_model_card = bool(component.get("modelCard")) or any(
            isinstance(ref, dict) and ref.get("type") == "model-card" for ref in external_refs
        )
        rows.append(
            {
                "id": _text(component.get("bom-ref"), limit=1024) or name,
                "name": name,
                "version": _text(component.get("version"), limit=1024),
                "type": component_type,
                "description": _text(component.get("description")),
                "purl": _text(component.get("purl"), limit=2048),
                "licenses": _licenses(component.get("licenses")),
                "model_card": has_model_card,
            }
        )
    return rows


def _spdx_items(document: dict[str, Any]) -> list[dict[str, Any]]:
    graph = document.get("@graph") or document.get("elements") or []
    if not isinstance(graph, list):
        raise ValueError("SPDX 3 JSON-LD @graph must be an array")
    context = document.get("@context")
    if "spdx" not in json.dumps(context or "").lower() and not any(
        "spdx" in _text(item.get("spdxId") if isinstance(item, dict) else "").lower() for item in graph
    ):
        raise ValueError("expected an SPDX 3 JSON-LD document")
    rows: list[dict[str, Any]] = []
    for element in graph:
        if not isinstance(element, dict):
            continue
        raw_type = element.get("type") or element.get("@type") or ""
        types = raw_type if isinstance(raw_type, list) else [raw_type]
        type_text = " ".join(_text(item, limit=128).lower() for item in types)
        if not any(token in type_text for token in ("ai", "package", "dataset", "software")):
            continue
        name = _text(element.get("name"), limit=1024)
        if not name:
            continue
        rows.append(
            {
                "id": _text(element.get("spdxId") or element.get("@id"), limit=1024) or name,
                "name": name,
                "version": _text(element.get("packageVersion") or element.get("version"), limit=1024),
                "type": "data" if "dataset" in type_text else "machine-learning-model",
                "description": _text(element.get("description") or element.get("comment")),
                "purl": _text(element.get("packageUrl"), limit=2048),
                "licenses": [],
                "model_card": "ai" in type_text,
            }
        )
    return rows


def import_aibom(*, input_path: Path, lake: Path) -> dict[str, Any]:
    """Normalize a supported JSON document into the lake's canonical AIBOM store."""
    size = input_path.stat().st_size
    if size > MAX_DOCUMENT_BYTES:
        raise ValueError(f"AIBOM document exceeds {MAX_DOCUMENT_BYTES} bytes")
    document = read_json(input_path)
    if not isinstance(document, dict):
        raise ValueError("AIBOM input must be a JSON object")
    if document.get("bomFormat") == "CycloneDX":
        source_format = f"cyclonedx-{document.get('specVersion')}"
        items = _cyclonedx_items(document)
    else:
        source_format = "spdx-3.0.1"
        items = _spdx_items(document)
    if not items:
        raise ValueError("AIBOM contains no supported AI model, dataset, or software components")

    store_path = lake / STORE_RELATIVE_PATH
    existing = read_json(store_path) if store_path.exists() else {"items": []}
    by_id = {str(item["id"]): item for item in existing.get("items", []) if isinstance(item, dict) and item.get("id")}
    imported_at = datetime.now(UTC).isoformat()
    source_sha256 = hashlib.sha256(input_path.read_bytes()).hexdigest()
    for item in items:
        by_id[item["id"]] = {**item, "source_format": source_format, "source_sha256": source_sha256}
    payload: dict[str, Any] = {
        "schema_version": 1,
        "updated_at": imported_at,
        "items": sorted(by_id.values(), key=lambda item: str(item["id"])),
    }
    write_json(store_path, payload)
    return {
        "format": source_format,
        "imported": len(items),
        "total": len(payload["items"]),
        "store_path": str(store_path),
        "source_sha256": source_sha256,
    }


def _cyclonedx_export(items: list[dict[str, Any]]) -> dict[str, Any]:
    components = []
    for item in items:
        component: dict[str, Any] = {
            "type": item.get("type") or "machine-learning-model",
            "bom-ref": item["id"],
            "name": item["name"],
        }
        for source, target in (("version", "version"), ("description", "description"), ("purl", "purl")):
            if item.get(source):
                component[target] = item[source]
        if item.get("licenses"):
            component["licenses"] = [{"license": {"id": value}} for value in item["licenses"]]
        if item.get("model_card") and component["type"] == "machine-learning-model":
            component["modelCard"] = {"bom-ref": f"{item['id']}:model-card"}
        components.append(component)
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "components": components,
    }


def _spdx_export(items: list[dict[str, Any]]) -> dict[str, Any]:
    graph = []
    for index, item in enumerate(items, start=1):
        element: dict[str, Any] = {
            "@id": item.get("id") or f"urn:trustops:aibom:{index}",
            "@type": "AI.AIPackage" if item.get("type") != "data" else "Dataset.DatasetPackage",
            "name": item["name"],
        }
        if item.get("version"):
            element["packageVersion"] = item["version"]
        if item.get("description"):
            element["description"] = item["description"]
        if item.get("purl"):
            element["packageUrl"] = item["purl"]
        graph.append(element)
    return {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": graph,
        "profileConformance": ["core", "ai", "dataset"],
        "specVersion": "3.0.1",
    }


def export_aibom(*, lake: Path, output_path: Path, output_format: str) -> dict[str, Any]:
    """Export the canonical inventory to a stable machine-readable format."""
    if output_format not in SUPPORTED_EXPORTS:
        raise ValueError(f"format must be one of: {', '.join(SUPPORTED_EXPORTS)}")
    store_path = lake / STORE_RELATIVE_PATH
    if not store_path.exists():
        raise ValueError("no AIBOM inventory found; run `grc-lake aibom import` first")
    store = read_json(store_path)
    items = store.get("items", []) if isinstance(store, dict) else []
    document = _cyclonedx_export(items) if output_format == "cyclonedx-1.7" else _spdx_export(items)
    write_json(output_path, document)
    return {"format": output_format, "exported": len(items), "output_path": str(output_path)}


def aibom_status(*, lake: Path) -> dict[str, Any]:
    store_path = lake / STORE_RELATIVE_PATH
    if not store_path.exists():
        return {"shipped": True, "formats": list(SUPPORTED_EXPORTS), "items": 0, "updated_at": None}
    store = read_json(store_path)
    return {
        "shipped": True,
        "formats": list(SUPPORTED_EXPORTS),
        "items": len(store.get("items", [])),
        "updated_at": store.get("updated_at"),
    }


def list_aibom_items(*, lake: Path) -> list[dict[str, Any]]:
    """Return canonical AIBOM rows without exposing source document contents."""
    store_path = lake / STORE_RELATIVE_PATH
    if not store_path.exists():
        return []
    store = read_json(store_path)
    rows = store.get("items", []) if isinstance(store, dict) else []
    return [dict(item) for item in rows if isinstance(item, dict)]


__all__ = ["SUPPORTED_EXPORTS", "aibom_status", "export_aibom", "import_aibom", "list_aibom_items"]
