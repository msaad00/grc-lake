"""The console must not serve unauthenticated data to a network.

`security_lakehouse.server` (local mode) has no authentication: it never reads
GRC_LAKE_OIDC_*, GRC_LAKE_SAML_*, or GRC_LAKE_SESSION_SECRET, because those
belong to `server_app`. That is fine on loopback and dangerous anywhere else.

The container is the way this reaches a network, so these tests pin both ends:
the CLI refuses to bind local mode to a routable address, and the image is
built and invoked so that the authenticated server is what actually runs.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from security_lakehouse.cli import _refuse_exposed_local_mode

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.5", "::1", "localhost"])
def test_local_mode_is_allowed_on_loopback(host: str, monkeypatch) -> None:
    monkeypatch.delenv("GRC_LAKE_ALLOW_INSECURE_NO_AUTH", raising=False)
    _refuse_exposed_local_mode(host)


@pytest.mark.parametrize("host", ["0.0.0.0", "10.0.1.7", "example.internal"])
def test_local_mode_refuses_a_routable_bind(host: str, monkeypatch) -> None:
    """Refuse rather than warn — a warning scrolls past in a container log."""
    monkeypatch.delenv("GRC_LAKE_ALLOW_INSECURE_NO_AUTH", raising=False)
    with pytest.raises(SystemExit) as excinfo:
        _refuse_exposed_local_mode(host)
    message = str(excinfo.value)
    assert "no authentication" in message
    assert "--server" in message


def test_local_mode_can_be_exposed_with_an_explicit_acknowledgement(monkeypatch) -> None:
    monkeypatch.setenv("GRC_LAKE_ALLOW_INSECURE_NO_AUTH", "true")
    _refuse_exposed_local_mode("0.0.0.0")


def test_container_installs_the_extra_that_provides_authentication() -> None:
    """Without the `server` extra the CMD below cannot run authenticated mode."""
    installs = re.findall(r'pip install\b[^&]*"\.\[([^\]]+)\]"', DOCKERFILE.read_text(encoding="utf-8"))
    assert installs, "Dockerfile no longer pip-installs the package with extras"
    assert any("server" in extras.split(",") for extras in installs), (
        f"Dockerfile installs {installs!r} — without the 'server' extra the image "
        "falls back to unauthenticated local mode"
    )


def test_container_command_runs_the_authenticated_server() -> None:
    cmd = re.search(r"^CMD \[(.+)\]", DOCKERFILE.read_text(encoding="utf-8"), re.MULTILINE)
    assert cmd, "Dockerfile has no CMD"
    argv = re.findall(r'"([^"]+)"', cmd.group(1))
    assert "serve" in argv
    # The image binds 0.0.0.0; --server is what makes that bind authenticated.
    assert "--server" in argv, f"container CMD {argv!r} would serve local mode on a network"


def test_container_includes_cloud_collection_and_agent_dependencies() -> None:
    installs = re.findall(r'pip install\b[^&]*"\.\[([^\]]+)\]"', DOCKERFILE.read_text(encoding="utf-8"))
    assert any({"server", "cloud", "mcp", "iceberg"} <= set(extras.split(",")) for extras in installs), (
        "Default container must support collection, MCP, and optional evidence publication"
    )
