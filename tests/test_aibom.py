"""CycloneDX/SPDX AIBOM import/export contract tests."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from security_lakehouse.ai_governance import list_ai_inventory
from security_lakehouse.aibom import aibom_status, export_aibom, import_aibom
from security_lakehouse.cli import main


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_cyclonedx_import_and_round_trip(tmp_path: Path) -> None:
    source = tmp_path / "model.cdx.json"
    _write(
        source,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "version": 1,
            "components": [
                {
                    "type": "machine-learning-model",
                    "bom-ref": "model:reranker:v3",
                    "name": "customer-support-reranker",
                    "version": "3",
                    "purl": "pkg:huggingface/acme/reranker@3",
                    "modelCard": {"bom-ref": "card:reranker:v3"},
                    "licenses": [{"license": {"id": "Apache-2.0"}}],
                },
                {"type": "data", "bom-ref": "data:training:v2", "name": "support-training", "version": "2"},
            ],
        },
    )
    result = import_aibom(input_path=source, lake=tmp_path / "lake")
    assert result["imported"] == 2
    assert len(result["source_sha256"]) == 64
    assert aibom_status(lake=tmp_path / "lake")["items"] == 2
    assert {row["asset_id"] for row in list_ai_inventory(lake=tmp_path / "lake")} == {
        "data:training:v2",
        "model:reranker:v3",
    }

    output = tmp_path / "export.cdx.json"
    exported = export_aibom(lake=tmp_path / "lake", output_path=output, output_format="cyclonedx-1.7")
    assert exported["exported"] == 2
    document = json.loads(output.read_text())
    assert document["specVersion"] == "1.7"
    model = next(component for component in document["components"] if component["bom-ref"] == "model:reranker:v3")
    assert model["modelCard"]["bom-ref"] == "model:reranker:v3:model-card"


def test_spdx_jsonld_import_and_export(tmp_path: Path) -> None:
    source = tmp_path / "model.spdx.json"
    _write(
        source,
        {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [
                {
                    "@id": "urn:spdx:acme:model:1",
                    "@type": "AI.AIPackage",
                    "name": "fraud-model",
                    "packageVersion": "1.4",
                    "description": "Transaction risk model",
                }
            ],
        },
    )
    assert import_aibom(input_path=source, lake=tmp_path / "lake")["format"] == "spdx-3.0.1"
    output = tmp_path / "export.spdx.json"
    export_aibom(lake=tmp_path / "lake", output_path=output, output_format="spdx-3.0.1")
    document = json.loads(output.read_text())
    creation = next(node for node in document["@graph"] if node["type"] == "CreationInfo")
    assert creation["specVersion"] == "3.0.1"
    model = next(node for node in document["@graph"] if node.get("name") == "fraud-model")
    assert model["type"] == "ai_AIPackage"
    assert model["spdxId"] == "urn:spdx:acme:model:1"
    assert model["software_packageVersion"] == "1.4"


def test_import_rejects_unbounded_or_unknown_documents(tmp_path: Path) -> None:
    source = tmp_path / "unknown.json"
    _write(source, {"components": []})
    with pytest.raises(ValueError, match="SPDX"):
        import_aibom(input_path=source, lake=tmp_path / "lake")


def test_cli_import_export(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "model.cdx.json"
    _write(
        source,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"type": "machine-learning-model", "name": "classifier"}],
        },
    )
    lake = tmp_path / "lake"
    output = tmp_path / "aibom.json"
    assert main(["aibom", "import", "--input", str(source), "--lake", str(lake)]) == 0
    assert main(["aibom", "export", "--lake", str(lake), "--out", str(output), "--format", "cyclonedx-1.7"]) == 0
    assert "cyclonedx-1.7" in capsys.readouterr().out
    assert output.exists()


_MIXED_CDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "components": [
        {
            "type": "machine-learning-model",
            "bom-ref": "model:reranker:v3",
            "name": "customer-support-reranker",
            "version": "3",
            "purl": "pkg:huggingface/acme/reranker@3",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
            "modelCard": {
                "bom-ref": "card:reranker:v3",
                "modelParameters": {"task": "text-classification", "approach": {"type": "supervised"}},
            },
        },
        {"type": "data", "bom-ref": "data:training:v2", "name": "support-training", "version": "2"},
        {"type": "library", "bom-ref": "pkg:pypi/torch@2.4.0", "name": "torch", "version": "2.4.0"},
        {"type": "application", "bom-ref": "app:support-bot", "name": "support-bot"},
    ],
}


def _export_spdx(tmp_path: Path) -> dict:
    source = tmp_path / "mixed.cdx.json"
    _write(source, _MIXED_CDX)
    import_aibom(input_path=source, lake=tmp_path / "lake")
    output = tmp_path / "export.spdx.json"
    export_aibom(lake=tmp_path / "lake", output_path=output, output_format="spdx-3.0.1")
    return json.loads(output.read_text())


def test_spdx_export_is_structurally_conformant_jsonld(tmp_path: Path) -> None:
    """Shape required by the official SPDX 3.0.1 JSON schema (spdx.org/schema/3.0.1)."""
    document = _export_spdx(tmp_path)
    assert set(document) == {"@context", "@graph"}
    assert document["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
    graph = document["@graph"]
    creation = [node for node in graph if node["type"] == "CreationInfo"]
    assert len(creation) == 1
    creation_id = creation[0]["@id"]
    assert creation_id.startswith("_:")
    assert creation[0]["specVersion"] == "3.0.1"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", creation[0]["created"])
    by_id = {node["spdxId"]: node for node in graph if "spdxId" in node}
    assert creation[0]["createdBy"]
    assert all(by_id[ref]["type"] == "SoftwareAgent" for ref in creation[0]["createdBy"])
    assert all(by_id[ref]["type"] == "Tool" for ref in creation[0]["createdUsing"])
    for node in graph:
        assert "@type" not in node
        if node["type"] != "CreationInfo":
            assert "@id" not in node
            assert node["creationInfo"] == creation_id
            assert re.match(r"^(urn|https?):", node["spdxId"])

    documents = [node for node in graph if node["type"] == "SpdxDocument"]
    assert len(documents) == 1
    spdx_document = documents[0]
    assert {"core", "software", "ai", "dataset", "simpleLicensing"} <= set(spdx_document["profileConformance"])
    packages = {node["name"]: node for node in graph if node["type"].endswith("Package")}
    assert set(spdx_document["rootElement"]) == {node["spdxId"] for node in packages.values()}
    assert set(spdx_document["element"]) == set(by_id) - {spdx_document["spdxId"]}

    assert packages["customer-support-reranker"]["type"] == "ai_AIPackage"
    assert packages["customer-support-reranker"]["software_packageVersion"] == "3"
    assert packages["customer-support-reranker"]["software_packageUrl"] == "pkg:huggingface/acme/reranker@3"
    assert packages["support-training"]["type"] == "dataset_DatasetPackage"
    assert packages["support-training"]["dataset_datasetType"] == ["noAssertion"]
    assert packages["torch"]["type"] == "software_Package"
    assert packages["torch"]["software_primaryPurpose"] == "library"
    assert packages["support-bot"]["type"] == "software_Package"
    assert packages["support-bot"]["software_primaryPurpose"] == "application"

    licenses = {node["spdxId"]: node for node in graph if node["type"] == "simplelicensing_LicenseExpression"}
    relationships = [node for node in graph if node["type"] == "Relationship"]
    declared = [rel for rel in relationships if rel["relationshipType"] == "hasDeclaredLicense"]
    assert len(declared) == 1
    assert declared[0]["from"] == packages["customer-support-reranker"]["spdxId"]
    assert [licenses[ref]["simplelicensing_licenseExpression"] for ref in declared[0]["to"]] == ["Apache-2.0"]


def test_spdx_export_round_trips_types_and_licenses(tmp_path: Path) -> None:
    document = _export_spdx(tmp_path)
    source = tmp_path / "round.spdx.json"
    _write(source, document)
    lake = tmp_path / "lake2"
    result = import_aibom(input_path=source, lake=lake)
    assert result["imported"] == 4
    rows = {row["name"]: row for row in json.loads((lake / "aibom" / "inventory.json").read_text())["items"]}
    assert rows["customer-support-reranker"]["type"] == "machine-learning-model"
    assert rows["customer-support-reranker"]["licenses"] == ["Apache-2.0"]
    assert rows["customer-support-reranker"]["version"] == "3"
    assert rows["support-training"]["type"] == "data"
    assert rows["torch"]["type"] == "library"
    assert rows["support-bot"]["type"] == "application"


def test_cyclonedx_export_has_serial_metadata_and_model_parameters(tmp_path: Path) -> None:
    source = tmp_path / "mixed.cdx.json"
    _write(source, _MIXED_CDX)
    import_aibom(input_path=source, lake=tmp_path / "lake")
    output = tmp_path / "export.cdx.json"
    export_aibom(lake=tmp_path / "lake", output_path=output, output_format="cyclonedx-1.7")
    document = json.loads(output.read_text())
    assert re.fullmatch(
        r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", document["serialNumber"]
    )
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", document["metadata"]["timestamp"])
    tools = document["metadata"]["tools"]["components"]
    assert tools[0]["type"] == "application"
    assert tools[0]["name"] == "grc-lake"
    model = next(c for c in document["components"] if c["bom-ref"] == "model:reranker:v3")
    assert model["modelCard"]["modelParameters"] == {
        "task": "text-classification",
        "approach": {"type": "supervised"},
    }
    library = next(c for c in document["components"] if c["name"] == "torch")
    assert library["type"] == "library"
    assert "modelCard" not in library


def test_import_drops_oversized_model_parameters(tmp_path: Path) -> None:
    source = tmp_path / "big.cdx.json"
    payload = json.loads(json.dumps(_MIXED_CDX))
    payload["components"][0]["modelCard"]["modelParameters"] = {"blob": "x" * 70_000}
    _write(source, payload)
    import_aibom(input_path=source, lake=tmp_path / "lake")
    rows = json.loads((tmp_path / "lake" / "aibom" / "inventory.json").read_text())["items"]
    model = next(row for row in rows if row["id"] == "model:reranker:v3")
    assert model["model_card"] is True
    assert "model_parameters" not in model
