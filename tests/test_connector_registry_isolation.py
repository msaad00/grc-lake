"""The connector registry tests hold in any order and with plugins installed.

``connector_runner.REGISTRY`` and the entry-point fixture modules are process
globals. The in-repo registry contract must not depend on which tests ran
before it, nor on third-party connector packages installed in the environment.
"""

from __future__ import annotations

import importlib.metadata
import os
import subprocess
import sys
from pathlib import Path

import pytest

from security_lakehouse import connector_runner

TESTS = Path(__file__).parent
ROOT = TESTS.parent
FIXTURES_DIR = TESTS / "fixtures" / "entry_point_connectors"
ENTRY_POINT_FILES = ("test_connector_entry_points.py", "test_connector_catalog_entry_points.py")
REGISTRY_FILE = "test_connector_registry.py"
LEAK_PROBE = "zz-registry-leak-probe"


def test_registry_contract_ignores_installed_package_connectors(monkeypatch: pytest.MonkeyPatch) -> None:
    """An installed plugin extends the effective registry, never the in-repo one."""
    import test_connector_registry as registry_tests

    monkeypatch.syspath_prepend(str(FIXTURES_DIR))
    groups = {
        "trustops.connectors": [("demo-vendor-evidence", "demo_vendor_connector:build_demo_vendor")],
        "trustops.connector_catalog": [("demo-vendor-evidence", "demo_vendor_connector:CATALOG_ENTRY")],
    }

    def installed(**kwargs: str) -> list[importlib.metadata.EntryPoint]:
        group = kwargs["group"]
        return [importlib.metadata.EntryPoint(name=n, value=v, group=group) for n, v in groups.get(group, [])]

    monkeypatch.setattr(importlib.metadata, "entry_points", installed)
    assert "demo-vendor-evidence" in connector_runner.effective_registry()
    registry_tests.test_implemented_adapters_catalog_flags_agree_with_registry()


def test_a_direct_registry_mutation_is_undone_after_the_test() -> None:
    # Deliberately not via monkeypatch: the autouse guard in conftest.py must
    # restore the process-global registry for whatever test runs next.
    connector_runner.REGISTRY[LEAK_PROBE] = lambda _inputs: []  # type: ignore[assignment]
    sys.modules["demo_vendor_connector"] = sys.modules.get("demo_vendor_connector") or type(sys)(
        "demo_vendor_connector"
    )


def test_the_previous_tests_mutations_did_not_leak() -> None:
    assert LEAK_PROBE not in connector_runner.REGISTRY
    assert "demo_vendor_connector" not in sys.modules


def _run(order: list[str]) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:randomly", *order],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )


@pytest.mark.parametrize(
    "order",
    [
        pytest.param([*ENTRY_POINT_FILES, REGISTRY_FILE], id="entry-points-first"),
        pytest.param([REGISTRY_FILE, *reversed(ENTRY_POINT_FILES)], id="registry-first"),
        pytest.param([ENTRY_POINT_FILES[1], REGISTRY_FILE, ENTRY_POINT_FILES[0]], id="interleaved"),
    ],
)
def test_entry_point_and_registry_files_pass_in_either_order(order: list[str]) -> None:
    result = _run([f"tests/{name}" for name in order])
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-2000:]
