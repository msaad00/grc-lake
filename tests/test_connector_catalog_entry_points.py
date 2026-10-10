"""Catalog metadata for connectors shipped as installed packages.

A package registers a sync builder under ``trustops.connectors`` and its
catalog row under ``trustops.connector_catalog`` (docs/ADDING_CONNECTORS.md).
``load_connector_catalog()`` admits the row only when it passes the same
validation as an in-repo row, has a loadable builder, and does not collide
with a built-in connector_id; anything else is logged and excluded.
"""

from __future__ import annotations

import importlib.metadata
import logging
from collections.abc import Callable
from pathlib import Path

import pytest

from security_lakehouse import connectors
from security_lakehouse.connector_state import append_config_event, build_catalog_view

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "entry_point_connectors"
BUILDERS = "trustops.connectors"
CATALOG = connectors.CONNECTOR_CATALOG_ENTRY_POINT_GROUP
DEMO_ID = "demo-vendor-evidence"
DEMO_BUILDER = ("demo-vendor-evidence", "demo_vendor_connector:build_demo_vendor")


@pytest.fixture(autouse=True)
def _fixture_connectors_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(FIXTURES_DIR))


def _install(
    monkeypatch: pytest.MonkeyPatch,
    *,
    builders: list[tuple[str, str]],
    catalog: list[tuple[str, str]],
) -> None:
    groups = {BUILDERS: builders, CATALOG: catalog}

    def fake(**kwargs: str) -> list[importlib.metadata.EntryPoint]:
        group = kwargs["group"]
        return [importlib.metadata.EntryPoint(name=n, value=v, group=group) for n, v in groups.get(group, [])]

    monkeypatch.setattr(importlib.metadata, "entry_points", fake)


def test_valid_package_row_joins_catalog_and_console_flow(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install(monkeypatch, builders=[DEMO_BUILDER], catalog=[(DEMO_ID, "demo_vendor_connector:CATALOG_ENTRY")])

    catalog = connectors.load_connector_catalog()

    row = catalog[DEMO_ID]
    assert row["is_implemented"] is True
    assert row["provenance"] == {"source": "entry_point", "entry_point": "demo_vendor_connector:CATALOG_ENTRY"}
    assert "okta-identity" in catalog

    view = {r["connector_id"]: r for r in build_catalog_view(tmp_path)}
    assert view[DEMO_ID]["state"] == "disabled"
    record = append_config_event(
        tmp_path, connector_id=DEMO_ID, state="enabled", actor="test", credentials={"credential_ref": "x"}
    )
    assert record["connector_id"] == DEMO_ID


def test_validation_and_explicit_catalog_path_ignore_installed_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, builders=[DEMO_BUILDER], catalog=[(DEMO_ID, "demo_vendor_connector:CATALOG_ENTRY")])

    assert DEMO_ID not in connectors.load_connector_catalog(connectors.DEFAULT_CONNECTOR_CATALOG)
    assert connectors.validate_connector_catalog() == []


@pytest.mark.parametrize(
    ("builders", "catalog_entry", "log_fragment"),
    [
        pytest.param([], (DEMO_ID, "demo_vendor_connector:CATALOG_ENTRY"), "no loadable", id="no-builder"),
        pytest.param(
            [DEMO_BUILDER],
            (DEMO_ID, "demo_vendor_connector:OVERBROAD_CATALOG_ENTRY"),
            "permission is too broad",
            id="overbroad-permission",
        ),
        pytest.param(
            [("okta-identity", "demo_vendor_connector:build_demo_vendor")],
            ("okta-identity", "demo_vendor_connector:CATALOG_ENTRY"),
            "built-in",
            id="builtin-collision",
        ),
        pytest.param(
            [("other-id", "demo_vendor_connector:build_demo_vendor")],
            ("other-id", "demo_vendor_connector:CATALOG_ENTRY"),
            "does not match",
            id="id-mismatch",
        ),
        pytest.param(
            [DEMO_BUILDER],
            (DEMO_ID, "broken_vendor_connector:CATALOG_ENTRY"),
            "failed to load",
            id="import-error",
        ),
        pytest.param([DEMO_BUILDER], (DEMO_ID, "demo_vendor_connector:CONNECTOR_ID"), "mapping", id="not-a-mapping"),
        pytest.param(
            [DEMO_BUILDER],
            (DEMO_ID, "demo_vendor_connector:raising_catalog_entry"),
            "raised",
            id="row-callable-raises",
        ),
    ],
)
def test_rejected_package_rows_are_logged_and_excluded(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    builders: list[tuple[str, str]],
    catalog_entry: tuple[str, str],
    log_fragment: str,
) -> None:
    _install(monkeypatch, builders=builders, catalog=[catalog_entry])
    builtin = connectors.load_connector_catalog(connectors.DEFAULT_CONNECTOR_CATALOG)

    with caplog.at_level(logging.WARNING, logger=connectors.__name__):
        catalog = connectors.load_connector_catalog()

    assert catalog == builtin
    assert log_fragment in caplog.text


def _install_groups(monkeypatch: pytest.MonkeyPatch, groups: dict[str, list[tuple[str, str]]]) -> None:
    def fake(**kwargs: str) -> list[importlib.metadata.EntryPoint]:
        group = kwargs["group"]
        return [importlib.metadata.EntryPoint(name=n, value=v, group=group) for n, v in groups.get(group, [])]

    monkeypatch.setattr(importlib.metadata, "entry_points", fake)


def test_grc_lake_groups_are_primary() -> None:
    assert connectors.CONNECTOR_BUILDER_ENTRY_POINT_GROUP == "grc_lake.connectors"
    assert connectors.CONNECTOR_CATALOG_ENTRY_POINT_GROUP == "grc_lake.connector_catalog"
    assert connectors.LEGACY_CONNECTOR_BUILDER_ENTRY_POINT_GROUP == "trustops.connectors"
    assert connectors.LEGACY_CONNECTOR_CATALOG_ENTRY_POINT_GROUP == "trustops.connector_catalog"


@pytest.mark.parametrize(
    ("builder_group", "catalog_group"),
    [
        ("grc_lake.connectors", "grc_lake.connector_catalog"),
        ("trustops.connectors", "trustops.connector_catalog"),
        ("trustops.connectors", "grc_lake.connector_catalog"),
        ("grc_lake.connectors", "trustops.connector_catalog"),
    ],
)
def test_row_is_admitted_from_either_group(
    monkeypatch: pytest.MonkeyPatch, builder_group: str, catalog_group: str
) -> None:
    _install_groups(
        monkeypatch,
        {builder_group: [DEMO_BUILDER], catalog_group: [(DEMO_ID, "demo_vendor_connector:CATALOG_ENTRY")]},
    )

    assert connectors.load_connector_catalog()[DEMO_ID]["is_implemented"] is True


def test_grc_lake_catalog_row_wins_over_legacy_row(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_groups(
        monkeypatch,
        {
            "grc_lake.connectors": [DEMO_BUILDER],
            "grc_lake.connector_catalog": [(DEMO_ID, "demo_vendor_connector:CATALOG_ENTRY")],
            "trustops.connector_catalog": [(DEMO_ID, "demo_vendor_connector:OVERBROAD_CATALOG_ENTRY")],
        },
    )

    row = connectors.load_connector_catalog()[DEMO_ID]

    assert row["provenance"]["entry_point"] == "demo_vendor_connector:CATALOG_ENTRY"


def test_entry_point_enumeration_failure_keeps_builtin_catalog(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def boom(**_kwargs: str) -> Callable[[], None]:
        raise RuntimeError("metadata unreadable")

    monkeypatch.setattr(importlib.metadata, "entry_points", boom)
    with caplog.at_level(logging.WARNING, logger=connectors.__name__):
        catalog = connectors.load_connector_catalog()

    assert catalog == connectors.load_connector_catalog(connectors.DEFAULT_CONNECTOR_CATALOG)
    assert "failed to enumerate" in caplog.text


def test_enabled_package_connector_syncs_end_to_end(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from security_lakehouse import connector_runner

    _install(monkeypatch, builders=[DEMO_BUILDER], catalog=[(DEMO_ID, "demo_vendor_connector:CATALOG_ENTRY")])
    append_config_event(tmp_path, connector_id=DEMO_ID, state="enabled", actor="test")

    result = connector_runner.run_connector_sync(tmp_path, connector_id=DEMO_ID, materialize=False)

    assert result.result == "ok"
    assert result.evidence_count == 1


def test_package_row_cannot_claim_primary_lake(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _install(
        monkeypatch,
        builders=[DEMO_BUILDER],
        catalog=[(DEMO_ID, "demo_vendor_connector:PRIMARY_LAKE_CATALOG_ENTRY")],
    )
    with caplog.at_level(logging.WARNING, logger=connectors.__name__):
        assert DEMO_ID not in connectors.load_connector_catalog()
    assert "primary_lake" in caplog.text


def test_package_row_may_be_a_zero_argument_callable(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, builders=[DEMO_BUILDER], catalog=[(DEMO_ID, "demo_vendor_connector:catalog_entry")])

    assert connectors.load_connector_catalog()[DEMO_ID]["is_implemented"] is True
