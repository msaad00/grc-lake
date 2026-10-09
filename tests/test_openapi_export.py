"""OpenAPI export drift checks for committed docs/api/openapi.v1.json."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from security_lakehouse.server_app import create_app

ROOT = Path(__file__).resolve().parents[1]
COMMITTED = ROOT / "docs" / "api" / "openapi.v1.json"
CATALOG = ROOT / "docs" / "api" / "resource-catalog.v1.json"


def _generate_openapi() -> dict:
    """Generate the spec the way `make openapi-export` does.

    The committed artifact is the FastAPI schema *plus* the catch-all-served
    routes merged in, so the drift check has to build the same thing or it
    compares against a spec missing the core read surface.
    """
    import tempfile

    from security_lakehouse import api_v1

    with tempfile.TemporaryDirectory() as tmp:
        return api_v1.merge_openapi(create_app(tmp, require_auth=False).openapi())


def test_committed_openapi_file_exists() -> None:
    assert COMMITTED.is_file(), "run: make openapi-export"


def test_committed_openapi_matches_generator() -> None:
    committed = json.loads(COMMITTED.read_text(encoding="utf-8"))
    generated = _generate_openapi()
    assert committed == generated


def test_openapi_documents_fastapi_surface() -> None:
    spec = json.loads(COMMITTED.read_text(encoding="utf-8"))
    paths = spec.get("paths", {})
    for path in (
        "/api/v1",
        "/api/v1/agent-runs",
        "/api/v1/audit-log",
    ):
        assert path in paths, path


def test_openapi_documents_public_trust_route() -> None:
    spec = json.loads(COMMITTED.read_text(encoding="utf-8"))
    assert "/console/trust/{token}" in spec["paths"]


def test_openapi_documents_every_catalogued_route() -> None:
    """The core read surface must appear in the spec, not behind a catch-all.

    `violations`, `controls`, `evidence`, `posture/current`, `snapshots`,
    `workflows` and the rest are served through `@app.get("/api/v1/{rest:path}")`,
    which FastAPI collapses into one `/api/v1/{rest}` entry. A client generated
    from a spec in that state cannot fetch posture at all.
    """
    from security_lakehouse import api_v1

    spec = json.loads(COMMITTED.read_text(encoding="utf-8"))
    documented = set(spec["paths"])
    catalogued = {row["path"] for row in api_v1.resource_catalog()}

    missing = sorted(catalogued - documented)
    assert missing == [], f"{len(missing)} catalogued routes are absent from the spec: {missing[:8]}"
    assert "/api/v1/{rest}" not in documented, "the catch-all should not be advertised as a route"


def test_openapi_declares_the_v1_envelope() -> None:
    spec = json.loads(COMMITTED.read_text(encoding="utf-8"))
    envelope = spec["components"]["schemas"]["V1Envelope"]
    assert set(envelope["required"]) == {"data", "meta", "errors"}


def test_resource_catalog_has_no_duplicate_paths() -> None:
    """A path described twice -- once from a loader table, once hand-written -- is one resource."""
    from security_lakehouse import api_v1

    rows = api_v1.resource_catalog()
    paths = [row["path"] for row in rows]
    assert len(paths) == len(set(paths)), "duplicate paths in the resource catalog"


def test_committed_resource_catalog_matches_generator() -> None:
    from security_lakehouse import api_v1

    assert CATALOG.is_file(), "run: make openapi-export"
    committed = json.loads(CATALOG.read_text(encoding="utf-8"))
    generated = {"resources": api_v1.resource_catalog()}
    assert committed == generated


def test_resource_catalog_supports_agent_skills() -> None:
    from security_lakehouse import api_v1

    paths = {row["path"] for row in api_v1.resource_catalog()}
    for path in (
        "/api/v1/posture/current",
        "/api/v1/connectors/{connector_id}/probe",
        "/api/v1/connectors/{connector_id}/configure",
        "/api/v1/connectors/{connector_id}/sync",
        "/api/v1/ingestion/eval",
        "/api/v1/agent-runs",
    ):
        assert path in paths, path
