"""Bounded, local-first AI bill of materials import and export.

The canonical store intentionally keeps only portable inventory fields. Source
documents remain customer-controlled; GRC Lake does not upload or enrich them.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from security_lakehouse import __version__
from security_lakehouse.io import read_json, write_json

STORE_RELATIVE_PATH = Path("aibom/inventory.json")
MAX_DOCUMENT_BYTES = 10 * 1024 * 1024
MAX_MODEL_PARAMETERS_BYTES = 64 * 1024
SUPPORTED_EXPORTS = ("cyclonedx-1.7", "spdx-3.0.1")
SPDX_CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
_SPDX_PACKAGE_TYPES = {
    "ai_aipackage": "machine-learning-model",
    "ai.aipackage": "machine-learning-model",
    "aipackage": "machine-learning-model",
    "dataset_datasetpackage": "data",
    "dataset.datasetpackage": "data",
    "datasetpackage": "data",
    "software_package": "library",
    "software.package": "library",
    "package": "library",
}
_SPDX_LICENSE_RELATIONSHIPS = {"hasDeclaredLicense", "hasConcludedLicense"}


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


def _model_parameters(value: Any) -> dict[str, Any] | None:
    """Keep a CycloneDX ``modelParameters`` object only when it is small."""
    if not isinstance(value, dict) or not value:
        return None
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False)
    if len(encoded.encode("utf-8")) > MAX_MODEL_PARAMETERS_BYTES:
        return None
    parsed: dict[str, Any] = json.loads(encoded)
    return parsed


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
        external_refs = component.get("externalReferences")
        if not isinstance(external_refs, list):
            external_refs = []
        model_card = component.get("modelCard")
        has_model_card = bool(model_card) or any(
            isinstance(ref, dict) and ref.get("type") == "model-card" for ref in external_refs
        )
        row: dict[str, Any] = {
            "id": _text(component.get("bom-ref"), limit=1024) or name,
            "name": name,
            "version": _text(component.get("version"), limit=1024),
            "type": component_type,
            "description": _text(component.get("description")),
            "purl": _text(component.get("purl"), limit=2048),
            "licenses": _licenses(component.get("licenses")),
            "model_card": has_model_card,
        }
        if component_type == "machine-learning-model" and isinstance(model_card, dict):
            parameters = _model_parameters(model_card.get("modelParameters"))
            if parameters is not None:
                row["model_parameters"] = parameters
        rows.append(row)
    return rows


def _spdx_node_type(node: dict[str, Any]) -> list[str]:
    raw_type = node.get("type") or node.get("@type") or ""
    types = raw_type if isinstance(raw_type, list) else [raw_type]
    return [_text(item, limit=128) for item in types]


def _spdx_item_type(element: dict[str, Any]) -> str:
    for type_name in _spdx_node_type(element):
        mapped = _SPDX_PACKAGE_TYPES.get(type_name.lower())
        if mapped == "library" and _text(element.get("software_primaryPurpose"), limit=64) == "application":
            return "application"
        if mapped:
            return mapped
    return ""


def _spdx_licenses(graph: list[Any]) -> dict[str, list[str]]:
    expressions: dict[str, str] = {}
    for node in graph:
        if isinstance(node, dict) and "simplelicensing_LicenseExpression" in _spdx_node_type(node):
            node_id = _text(node.get("spdxId") or node.get("@id"), limit=1024)
            expression = _text(node.get("simplelicensing_licenseExpression"), limit=256)
            if node_id and expression:
                expressions[node_id] = expression
    by_element: dict[str, list[str]] = {}
    for node in graph:
        if not isinstance(node, dict) or "Relationship" not in _spdx_node_type(node):
            continue
        relationship = node.get("relationshipType")
        if not isinstance(relationship, str) or relationship not in _SPDX_LICENSE_RELATIONSHIPS:
            continue
        targets = node.get("to")
        found = by_element.setdefault(_text(node.get("from"), limit=1024), [])
        for target in targets if isinstance(targets, list) else []:
            resolved = expressions.get(_text(target, limit=1024))
            if resolved and resolved not in found:
                found.append(resolved)
    return by_element


def _spdx_items(document: dict[str, Any]) -> list[dict[str, Any]]:
    graph = document.get("@graph") or document.get("elements") or []
    if not isinstance(graph, list):
        raise ValueError("SPDX 3 JSON-LD @graph must be an array")
    context = document.get("@context")
    if "spdx" not in json.dumps(context or "").lower() and not any(
        "spdx" in _text(item.get("spdxId") if isinstance(item, dict) else "").lower() for item in graph
    ):
        raise ValueError("expected an SPDX 3 JSON-LD document")
    licenses = _spdx_licenses(graph)
    rows: list[dict[str, Any]] = []
    for element in graph:
        if not isinstance(element, dict):
            continue
        item_type = _spdx_item_type(element)
        if not item_type:
            continue
        name = _text(element.get("name"), limit=1024)
        if not name:
            continue
        element_id = _text(element.get("spdxId") or element.get("@id"), limit=1024)
        version = element.get("software_packageVersion") or element.get("packageVersion") or element.get("version")
        rows.append(
            {
                "id": element_id or name,
                "name": name,
                "version": _text(version, limit=1024),
                "type": item_type,
                "description": _text(element.get("description") or element.get("comment")),
                "purl": _text(element.get("software_packageUrl") or element.get("packageUrl"), limit=2048),
                "licenses": licenses.get(element_id, []),
                "model_card": item_type == "machine-learning-model",
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


def _timestamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


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
            model_card: dict[str, Any] = {"bom-ref": f"{item['id']}:model-card"}
            if isinstance(item.get("model_parameters"), dict):
                model_card["modelParameters"] = item["model_parameters"]
            component["modelCard"] = model_card
        components.append(component)
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": uuid.uuid4().urn,
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(),
            "tools": {"components": [{"type": "application", "name": "grc-lake", "version": __version__}]},
        },
        "components": components,
    }


def _spdx_iri(value: str, *, namespace: str) -> str:
    if value.startswith(("urn:", "https://", "http://")) and not any(char.isspace() for char in value):
        return value
    return f"{namespace}{quote(value, safe='')}"


def _spdx_package(item: dict[str, Any], *, spdx_id: str, creation_id: str) -> dict[str, Any]:
    item_type = item.get("type") or "machine-learning-model"
    element: dict[str, Any] = {"spdxId": spdx_id, "creationInfo": creation_id, "name": item["name"]}
    if item_type == "machine-learning-model":
        element["type"] = "ai_AIPackage"
    elif item_type == "data":
        element["type"] = "dataset_DatasetPackage"
        element["dataset_datasetType"] = ["noAssertion"]
    else:
        element["type"] = "software_Package"
        element["software_primaryPurpose"] = "application" if item_type == "application" else "library"
    if item.get("version"):
        element["software_packageVersion"] = item["version"]
    if item.get("description"):
        element["description"] = item["description"]
    if item.get("purl"):
        element["software_packageUrl"] = item["purl"]
    return element


def _spdx_export(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Project the inventory to an SPDX 3.0.1 JSON-LD document."""
    namespace = f"urn:grc-lake:aibom:{uuid.uuid4()}:"
    creation_id = "_:creationinfo"
    agent_id = f"{namespace}agent"
    tool_id = f"{namespace}tool"
    graph: list[dict[str, Any]] = [
        {
            "type": "CreationInfo",
            "@id": creation_id,
            "specVersion": "3.0.1",
            "created": _timestamp(),
            "createdBy": [agent_id],
            "createdUsing": [tool_id],
        },
        {"type": "SoftwareAgent", "spdxId": agent_id, "creationInfo": creation_id, "name": "grc-lake"},
        {"type": "Tool", "spdxId": tool_id, "creationInfo": creation_id, "name": f"grc-lake {__version__}"},
    ]
    roots: list[str] = []
    for index, item in enumerate(items, start=1):
        spdx_id = _spdx_iri(str(item.get("id") or index), namespace=f"{namespace}element:")
        if spdx_id in roots:
            spdx_id = f"{namespace}element:{index}"
        roots.append(spdx_id)
        graph.append(_spdx_package(item, spdx_id=spdx_id, creation_id=creation_id))
        license_ids: list[str] = []
        for license_index, expression in enumerate(item.get("licenses") or [], start=1):
            license_id = f"{namespace}license:{index}:{license_index}"
            license_ids.append(license_id)
            graph.append(
                {
                    "type": "simplelicensing_LicenseExpression",
                    "spdxId": license_id,
                    "creationInfo": creation_id,
                    "simplelicensing_licenseExpression": expression,
                }
            )
        if license_ids:
            graph.append(
                {
                    "type": "Relationship",
                    "spdxId": f"{namespace}relationship:{index}:declared-license",
                    "creationInfo": creation_id,
                    "from": spdx_id,
                    "relationshipType": "hasDeclaredLicense",
                    "to": license_ids,
                }
            )
    elements = [node["spdxId"] for node in graph if "spdxId" in node]
    graph.append(
        {
            "type": "SpdxDocument",
            "spdxId": f"{namespace}document",
            "creationInfo": creation_id,
            "name": "GRC Lake AI bill of materials",
            "profileConformance": ["core", "software", "ai", "dataset", "simpleLicensing"],
            "rootElement": roots,
            "element": elements,
        }
    )
    return {"@context": SPDX_CONTEXT, "@graph": graph}


def export_aibom(*, lake: Path, output_path: Path, output_format: str) -> dict[str, Any]:
    """Export the canonical inventory to a machine-readable format."""
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
