"""Wire and export regression contracts for the second audit pass."""

from http import HTTPStatus

import anyio
import pytest
from mcp.shared.exceptions import McpError
from mcp.shared.memory import create_connected_server_and_client_session

from security_lakehouse import api_legacy, mcp_server, oscal


def test_unknown_legacy_evidence_returns_not_found(tmp_path):
    status, body = api_legacy.handle_post("/api/evidence/missing/verify", {}, tmp_path)
    assert status == HTTPStatus.NOT_FOUND
    assert body["error"] == "not_found"


def test_unknown_mcp_tool_is_a_protocol_error(tmp_path):
    server = mcp_server.build_server(tmp_path)

    async def call():
        async with create_connected_server_and_client_session(server, raise_exceptions=True) as client:
            with pytest.raises(McpError) as error:
                await client.call_tool("not_a_registered_tool", {})
            assert error.value.error.code == -32602

    anyio.run(call)


def test_oscal_known_catalog_uses_native_control_identifiers(monkeypatch):
    url = "https://example.test/nist-catalog.json"
    monkeypatch.setattr(
        oscal,
        "load_framework_registry",
        lambda: {
            "nist-800-53-rev5": {
                "name": "NIST",
                "official_source_url": "https://example.test/landing",
                "oscal_source_url": url,
                "oscal_control_prefix": "NIST-800-53-",
            }
        },
    )
    payload = {
        "safeguards": [
            {
                "safeguard_id": "SG-TEST",
                "title": "Test",
                "satisfies": [
                    {
                        "framework_id": "nist-800-53-rev5",
                        "control_id": "NIST-800-53-AC-2.1",
                        "role": "primary",
                        "review_status": "reviewed",
                    }
                ],
            }
        ]
    }
    result = oscal.build_component_definition(payload, {})
    implementation = result["component-definition"]["components"][0]["control-implementations"][0]
    assert implementation["source"] == url
    assert implementation["implemented-requirements"][0]["control-id"] == "ac-2.1"
