"""Tests for shareable demo link and account-linking helpers."""

from __future__ import annotations

from urllib.parse import urlparse

from security_lakehouse.demo_links import build_account_linking, build_demo_kit, build_share_links


def test_share_links_require_public_url_for_invites() -> None:
    links = build_share_links(
        public_url=None,
        sso_configured=False,
        require_auth=False,
        active_share_count=0,
    )
    assert len(links) == 1
    assert links[0]["kind"] == "workspace"
    assert "GRC_LAKE_PUBLIC_URL" in links[0]["description"]


def test_share_links_include_login_and_connect_when_hosted() -> None:
    links = build_share_links(
        public_url="https://trustops.example.test",
        sso_configured=True,
        require_auth=True,
        active_share_count=1,
    )
    kinds = {row["kind"] for row in links}
    assert "workspace" in kinds
    assert "login" in kinds
    assert "connect" in kinds
    assert "demo" in kinds
    assert "trust_share_active" in kinds
    login = next(row for row in links if row["kind"] == "login")
    assert login["url"] == "https://trustops.example.test/api/v1/auth/login"
    for row in links:
        url = row["url"]
        if not url.startswith("http"):
            continue
        parsed = urlparse(url)
        assert parsed.scheme == "https"
        assert parsed.netloc == "trustops.example.test"


def test_share_links_use_console_login_when_auth_required_without_sso() -> None:
    links = build_share_links(
        public_url="https://trustops.example.test",
        sso_configured=False,
        require_auth=True,
        active_share_count=0,
    )
    login = next(row for row in links if row["kind"] == "login")
    assert login["url"] == "https://trustops.example.test/console/login/"


def test_share_links_use_saml_login_when_configured() -> None:
    links = build_share_links(
        public_url="https://trustops.example.test",
        sso_configured=True,
        require_auth=True,
        active_share_count=0,
        login_path="/api/v1/auth/saml/login",
    )
    login = next(row for row in links if row["kind"] == "login")
    assert login["url"] == "https://trustops.example.test/api/v1/auth/saml/login"


def test_share_links_reject_unsafe_public_url() -> None:
    links = build_share_links(
        public_url="javascript:alert(1)",
        sso_configured=True,
        require_auth=True,
        active_share_count=0,
    )
    assert links[0]["kind"] == "workspace"
    assert links[0]["description"].startswith("Set GRC_LAKE_PUBLIC_URL")


def test_account_linking_deep_links_and_status() -> None:
    ingestion = {
        "connectors": [
            {
                "connector_id": "aws-posture",
                "state": "enabled",
                "latest_sync": {"result": "ok", "occurred_at": "2026-06-30T00:00:00Z", "evidence_count": 12},
                "latest_probe": {"result": "ok"},
            },
            {
                "connector_id": "snowflake-evidence-lake",
                "state": "disabled",
                "latest_sync": {"result": None},
                "latest_probe": {"result": None},
            },
        ]
    }
    rows = build_account_linking(ingestion, public_url="https://demo.example.com")
    aws = next(row for row in rows if row["connector_id"] == "aws-posture")
    snowflake = next(row for row in rows if row["connector_id"] == "snowflake-evidence-lake")
    assert aws["status"] == "ingesting"
    assert aws["evidence_count"] == 12
    assert aws["connect_url"] == "https://demo.example.com/console/connectors/?connect=aws-posture"
    assert snowflake["status"] == "not_linked"


def test_demo_kit_bundles_share_links_and_account_linking() -> None:
    kit = build_demo_kit(
        public_url="https://demo.example.com",
        sso_configured=True,
        require_auth=True,
        ingestion={"connectors": [], "proof": {"scenario": "live-cloud-posture"}},
        active_share_count=0,
        shareable=False,
    )
    assert kit["public_url"] == "https://demo.example.com"
    assert len(kit["share_links"]) >= 4
    assert kit["account_linking_summary"]["recommended"] == 6
    assert kit["ingestion_proof"]["scenario"] == "live-cloud-posture"
