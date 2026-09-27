"""Regression contract for the concise connector hub experience."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
PAGE = ROOT / "app/web/src/app/connectors/page.tsx"


def test_connector_hub_uses_compact_interactive_filters_and_grid() -> None:
    page = PAGE.read_text(encoding="utf-8")

    assert 'aria-label="Connection view"' in page
    assert 'aria-label="Category filter"' in page
    assert 'id="connector-category-filter"' in page
    assert "overflow-x-auto" in page
    assert 'className="grid gap-2 p-3 pt-0 md:grid-cols-2 xl:grid-cols-3"' in page
    assert "Needs attention" in page
    assert "Needs setup" in page
    assert "All categories" in page
    assert "{totals.runnable} available" in page
    assert "if (!isRunnableConnector(c)) return false;" in page
    assert "RunnerFilter" not in page
    assert "RUNNER_TABS" not in page
    assert 'aria-label="Runner filter"' not in page
    assert 'label: "Available"' not in page
    assert 'label: "All sources"' not in page
    assert 'label: "Planned"' not in page
    assert 'label: "Runnable"' not in page
    assert 'label: "All runners"' not in page
    assert 'label: "Contract only"' not in page
    assert "Evidence loop" not in page
    assert 'label: "Prove"' not in page
    assert "raw collection evidence and evaluated gold reports" not in page
    assert "{totals.enabled}/" not in page
    assert "{totals.total} enabled" not in page
    assert "Registry overview" not in page
    assert "ConnectorIngestionStrip" not in page
    assert "ConnectorIntegrationCoverage" not in page
    assert "ConnectorRegistryGapStrip" not in page
    assert "ConnectorEcosystemStrip" not in page
    assert "Integration breadth" not in page
    assert "Live ingestion" not in page
    assert "daily snapshot ready" not in page
    assert "Select a source to connect, probe access, and schedule its daily" not in page
    assert "Connect a source, test access, then sync evidence." in page


def test_preview_connectors_are_wired_into_the_console_and_badged() -> None:
    catalog = json.loads((ROOT / "connectors/catalog.json").read_text(encoding="utf-8"))["connectors"]
    preview = [row for row in catalog if row.get("release_stage") == "preview"]
    assert {row["connector_id"] for row in preview} >= {
        "jamf-devices",
        "crowdstrike-falcon",
        "kubernetes-cluster",
        "knowbe4-training",
    }
    lib = ROOT / "app/web/src/lib"
    forms = (lib / "connector-forms.ts").read_text(encoding="utf-8")
    visuals = (lib / "connector-visuals.ts").read_text(encoding="utf-8")
    presets = (lib / "integration-presets.ts").read_text(encoding="utf-8")
    for row in preview:
        key = f'"{row["connector_id"]}": '
        assert key + "[" in forms, row["connector_id"]
        assert key + "{" in visuals, row["connector_id"]
        assert f'connectorId: "{row["connector_id"]}"' in presets, row["connector_id"]
    # Secrets are only ever referenced by env var name in these forms.
    block = forms[forms.index('"jamf-devices": [') : forms.index('"workday-personnel": [')]
    assert "secret: true" not in block
    assert set(re.findall(r'name: "([a-z_]+)"', block)) <= {
        "base_url",
        "client_id",
        "client_secret_ref",
        "screen_lock_attribute",
        "cloud",
        "cluster_name",
        "context",
        "kubeconfig_ref",
        "allowed_registries",
        "region",
        "credential_ref",
    }

    page = PAGE.read_text(encoding="utf-8")
    drawer = (ROOT / "app/web/src/components/drawers/ConnectorDrawer.tsx").read_text(encoding="utf-8")
    for source in (page, drawer):
        assert 'release_stage === "preview"' in source
        assert re.search(r">\s*Preview\s*</Badge>", source)
