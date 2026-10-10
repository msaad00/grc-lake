"""Fuzz ``grc-lake aibom import`` for CycloneDX and SPDX 3 JSON-LD documents.

Half the inputs are raw bytes; the other half build a CycloneDX or SPDX
skeleton whose fields take fuzzed JSON values of any type, so the normalizers
see hostile shapes and not only parse failures.

Invariants:
* ``import_aibom`` either succeeds or raises ``ValueError`` (``InvalidJSON``
  included); no other exception escapes for any input document.
* On success the store holds unique, sorted ids and every item stays inside
  the documented bounds: supported type, non-empty name, field length limits,
  de-duplicated license strings, small ``model_parameters``, and the SHA-256
  of the exact input bytes.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from _input import Input, run

from security_lakehouse import strict_json
from security_lakehouse.aibom import MAX_MODEL_PARAMETERS_BYTES, STORE_RELATIVE_PATH, import_aibom

_ROOT = Path(tempfile.mkdtemp(prefix="grc-lake-fuzz-aibom-"))
atexit.register(shutil.rmtree, _ROOT, ignore_errors=True)
_SOURCE = _ROOT / "input.json"
_LAKE = _ROOT / "lake"
_TYPES = {"machine-learning-model", "data", "application", "library"}
_LIMITS = {"id": 1024, "name": 1024, "version": 1024, "description": 4096, "purl": 2048}

_WORDS = (
    "machine-learning-model",
    "data",
    "library",
    "application",
    "model-card",
    "ai_AIPackage",
    "dataset_DatasetPackage",
    "software_Package",
    "Relationship",
    "simplelicensing_LicenseExpression",
    "hasDeclaredLicense",
    "spdx:a",
    "spdx:b",
    "MIT",
)


def _json(inp: Input, depth: int = 0) -> Any:
    kind = inp.take_int(9) if depth < 3 else inp.take_int(6)
    if kind == 0:
        return None
    if kind == 1:
        return bool(inp.take_int(2))
    if kind == 2:
        return inp.take_int(256) - 128
    if kind == 3:
        return inp.take_int(256) / 7
    if kind == 4:
        return _WORDS[inp.take_int(len(_WORDS))]
    if kind == 5:
        return inp.take_text(12)
    if kind in (6, 7):
        return [_json(inp, depth + 1) for _ in range(inp.take_int(4))]
    return {_WORDS[inp.take_int(len(_WORDS))]: _json(inp, depth + 1) for _ in range(inp.take_int(4))}


def _node(inp: Input, fields: tuple[str, ...]) -> dict[str, Any]:
    return {field: _json(inp) for field in fields if inp.take_int(3)}


def _document(inp: Input) -> dict[str, Any]:
    if inp.take_int(2):
        fields = ("type", "name", "bom-ref", "version", "licenses", "externalReferences", "modelCard", "purl")
        components: list[Any] = [_node(inp, fields) for _ in range(inp.take_int(5))]
        for component in components:
            component.setdefault("name", "n")
            component.setdefault("type", _WORDS[inp.take_int(4)])
        return {
            "bomFormat": "CycloneDX",
            "specVersion": ("1.5", "1.6", "1.7")[inp.take_int(3)],
            "components": components,
        }
    fields = (
        "type",
        "@type",
        "spdxId",
        "name",
        "software_primaryPurpose",
        "software_packageVersion",
        "relationshipType",
        "from",
        "to",
        "simplelicensing_licenseExpression",
    )
    graph: list[Any] = [_node(inp, fields) for _ in range(inp.take_int(6))]
    return {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": graph}


def _check_store(source: bytes, result: dict[str, Any]) -> None:
    assert result["imported"] >= 1
    assert result["source_sha256"] == hashlib.sha256(source).hexdigest()
    items = strict_json.loads((_LAKE / STORE_RELATIVE_PATH).read_bytes())["items"]
    assert result["total"] == len(items)
    ids = [item["id"] for item in items]
    assert ids == sorted(ids) and len(set(ids)) == len(ids), "store ids are not unique and sorted"
    for item in items:
        assert item["type"] in _TYPES
        assert item["name"], "imported item has an empty name"
        for field, limit in _LIMITS.items():
            assert isinstance(item[field], str) and len(item[field]) <= limit, f"{field} exceeds {limit}"
        licenses = item["licenses"]
        assert len(set(licenses)) == len(licenses)
        assert all(isinstance(value, str) and 0 < len(value) <= 256 for value in licenses)
        assert isinstance(item["model_card"], bool)
        if "model_parameters" in item:
            encoded = json.dumps(item["model_parameters"], sort_keys=True, ensure_ascii=False).encode("utf-8")
            assert isinstance(item["model_parameters"], dict) and len(encoded) <= MAX_MODEL_PARAMETERS_BYTES


def TestOneInput(data: bytes) -> None:
    inp = Input(data)
    if inp.take_int(2):
        source = inp.take_rest()
    else:
        source = json.dumps(_document(inp), ensure_ascii=False).encode("utf-8", "surrogatepass")
    _SOURCE.write_bytes(source)
    shutil.rmtree(_LAKE, ignore_errors=True)
    try:
        result = import_aibom(input_path=_SOURCE, lake=_LAKE)
    except ValueError:
        return
    _check_store(source, result)


if __name__ == "__main__":
    run(TestOneInput)
