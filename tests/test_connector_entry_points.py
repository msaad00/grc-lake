"""Entry-point connector registration.

``connector_runner.REGISTRY`` is the in-repo dispatch table (see
test_connector_registry.py). ``connector_runner.effective_registry()`` is the
additive, second registration path: it merges REGISTRY with connectors
discovered from installed packages' ``trustops.connectors`` entry points
(docs/ADDING_CONNECTORS.md), without ever mutating REGISTRY itself.

These tests simulate an installed third-party connector package by adding
``tests/fixtures/entry_point_connectors`` to ``sys.path`` and monkeypatching
``importlib.metadata.entry_points`` to return real :class:`EntryPoint`
objects pointing at the modules there -- so ``EntryPoint.load()`` exercises
genuine import machinery, not a mocked call.
"""

from __future__ import annotations

import importlib.metadata
import logging
from pathlib import Path

import pytest

from security_lakehouse import connector_runner
from security_lakehouse.connector_runner import DEFAULT_TOKEN_ENV, SyncInputs
from security_lakehouse.validation import validate_raw_events

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "entry_point_connectors"
GROUP = connector_runner.CONNECTOR_ENTRY_POINT_GROUP


def _entry_point(name: str, value: str) -> importlib.metadata.EntryPoint:
    return importlib.metadata.EntryPoint(name=name, value=value, group=GROUP)


@pytest.fixture(autouse=True)
def _fixture_connectors_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(FIXTURES_DIR))


def test_entry_point_connector_appears_in_effective_registry_and_is_callable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **_kwargs: [_entry_point("demo-vendor-evidence", "demo_vendor_connector:build_demo_vendor")],
    )

    registry = connector_runner.effective_registry()

    assert "demo-vendor-evidence" in registry
    # Additive only: the in-repo REGISTRY itself is never mutated.
    assert "demo-vendor-evidence" not in connector_runner.REGISTRY
    # Built-ins are still present alongside the new connector.
    assert "okta-identity" in registry

    # Callable through the same dispatch path a built-in connector uses.
    rows = connector_runner._collect(
        "demo-vendor-evidence",
        repo=None,
        fixture_dir=None,
        token_env=DEFAULT_TOKEN_ENV,
    )
    assert rows
    assert rows[0]["event_id"] == "demo-vendor-evidence-1"
    assert rows[0]["source"] == "demo-vendor"
    assert validate_raw_events(rows) == []

    # And directly, the way a builder is invoked internally.
    builder = registry["demo-vendor-evidence"]
    direct_rows = builder(SyncInputs(repo=None, fixture_dir=None, token_env=DEFAULT_TOKEN_ENV, env={}))
    assert direct_rows[0]["event_id"] == rows[0]["event_id"]
    assert direct_rows[0]["source"] == rows[0]["source"]


def test_entry_point_connector_colliding_with_builtin_does_not_override(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **_kwargs: [_entry_point("okta-identity", "collision_vendor_connector:build_colliding_okta")],
    )

    with caplog.at_level(logging.WARNING, logger="security_lakehouse.connector_runner"):
        registry = connector_runner.effective_registry()

    # The built-in adapter wins; the third-party builder is never installed.
    assert registry["okta-identity"] is connector_runner.REGISTRY["okta-identity"]

    warnings = [record for record in caplog.records if record.levelno == logging.WARNING]
    assert any("okta-identity" in record.getMessage() for record in warnings)
    assert any("collide" in record.getMessage() for record in warnings)


def test_broken_entry_point_does_not_break_the_rest_of_the_registry(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **_kwargs: [
            _entry_point("broken-vendor-evidence", "broken_vendor_connector:whatever"),
            _entry_point("demo-vendor-evidence", "demo_vendor_connector:build_demo_vendor"),
        ],
    )

    with caplog.at_level(logging.WARNING, logger="security_lakehouse.connector_runner"):
        registry = connector_runner.effective_registry()

    # The broken package is excluded, never raised.
    assert "broken-vendor-evidence" not in registry
    # A valid entry point registered alongside the broken one still loads.
    assert "demo-vendor-evidence" in registry
    # Every built-in adapter is untouched and still present.
    assert set(connector_runner.REGISTRY).issubset(registry)

    warnings = [record for record in caplog.records if record.levelno == logging.WARNING]
    assert any("broken-vendor-evidence" in record.getMessage() for record in warnings)


def _install_groups(monkeypatch: pytest.MonkeyPatch, groups: dict[str, list[tuple[str, str]]]) -> None:
    def fake(**kwargs: str) -> list[importlib.metadata.EntryPoint]:
        group = kwargs["group"]
        return [importlib.metadata.EntryPoint(name=n, value=v, group=group) for n, v in groups.get(group, [])]

    monkeypatch.setattr(importlib.metadata, "entry_points", fake)


def test_grc_lake_group_is_primary_and_legacy_group_still_loads(monkeypatch: pytest.MonkeyPatch) -> None:
    assert GROUP == "grc_lake.connectors"
    assert connector_runner.LEGACY_CONNECTOR_ENTRY_POINT_GROUP == "trustops.connectors"
    _install_groups(
        monkeypatch,
        {
            "grc_lake.connectors": [("demo-vendor-evidence", "demo_vendor_connector:build_demo_vendor")],
            "trustops.connectors": [("legacy-vendor-evidence", "demo_vendor_connector:build_demo_vendor")],
        },
    )

    registry = connector_runner.effective_registry()

    assert "demo-vendor-evidence" in registry
    assert "legacy-vendor-evidence" in registry


def test_grc_lake_group_wins_a_name_registered_in_both_groups(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _install_groups(
        monkeypatch,
        {
            "grc_lake.connectors": [("demo-vendor-evidence", "demo_vendor_connector:build_demo_vendor")],
            "trustops.connectors": [("demo-vendor-evidence", "broken_vendor_connector:whatever")],
        },
    )

    with caplog.at_level(logging.WARNING, logger="security_lakehouse.connector_runner"):
        registry = connector_runner.effective_registry()

    import demo_vendor_connector

    assert registry["demo-vendor-evidence"] is demo_vendor_connector.build_demo_vendor
    # The shadowed legacy registration is never imported.
    assert "broken_vendor_connector" not in caplog.text
