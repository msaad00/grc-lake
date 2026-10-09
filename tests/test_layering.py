"""Lower layers must never import the API, server, MCP, or CLI entry layers."""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE = "security_lakehouse"
PACKAGE_DIR = Path(__file__).resolve().parents[1] / "src" / PACKAGE

ENTRY_LAYERS = frozenset({"api_v1", "server_app", "mcp_server", "cli"})

# (importing file relative to the package, imported entry module) -> reason.
ALLOWED_EDGES: dict[tuple[str, str], str] = {}


def _is_lower_layer(rel: Path) -> bool:
    parts = rel.parts
    if parts[0] in {"auth", "db"}:
        return True
    if len(parts) != 1:
        return False
    name = parts[0]
    return name in {"io.py", "ledger.py"} or (name.startswith("connectors_") and name.endswith(".py"))


def _module_name(rel: Path) -> str:
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join([PACKAGE, *parts])


def _resolve_from(node: ast.ImportFrom, module: str, is_package: bool) -> str:
    if node.level == 0:
        return node.module or ""
    base = module.split(".")
    if not is_package:
        base.pop()
    base = base[: len(base) - (node.level - 1)]
    return ".".join([*base, node.module] if node.module else base)


def imported_modules(source: str, module: str, *, is_package: bool = False) -> set[str]:
    """Every module an import statement anywhere in ``source`` can bind, at any nesting level."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            target = _resolve_from(node, module, is_package)
            found.add(target)
            found.update(f"{target}.{alias.name}" for alias in node.names)
    return found


def entry_layer_edges(source: str, module: str, *, is_package: bool = False) -> set[str]:
    edges: set[str] = set()
    for name in imported_modules(source, module, is_package=is_package):
        parts = name.split(".")
        if len(parts) >= 2 and parts[0] == PACKAGE and parts[1] in ENTRY_LAYERS:
            edges.add(parts[1])
    return edges


def _lower_layer_files() -> list[Path]:
    return sorted(p for p in PACKAGE_DIR.rglob("*.py") if _is_lower_layer(p.relative_to(PACKAGE_DIR)))


def _violations() -> dict[tuple[str, str], None]:
    found: dict[tuple[str, str], None] = {}
    for path in _lower_layer_files():
        rel = path.relative_to(PACKAGE_DIR)
        source = path.read_text(encoding="utf-8")
        for target in entry_layer_edges(source, _module_name(rel), is_package=rel.name == "__init__.py"):
            found[(rel.as_posix(), target)] = None
    return found


def test_lower_layer_selection_covers_the_intended_modules() -> None:
    names = {p.relative_to(PACKAGE_DIR).as_posix() for p in _lower_layer_files()}
    assert {"io.py", "ledger.py", "auth/json_body.py", "db/base.py", "connectors_aws.py"} <= names
    assert not {"connectors.py", "api_v1.py", "server_app.py", "connector_runner.py"} & names
    assert sum(1 for n in names if n.startswith("connectors_")) >= 20


def test_scanner_detects_every_import_form() -> None:
    module = "security_lakehouse.auth.example"
    forms = {
        "from security_lakehouse import api_v1": {"api_v1"},
        "import security_lakehouse.server_app": {"server_app"},
        "import security_lakehouse.server_app as app": {"server_app"},
        "from security_lakehouse.mcp_server import build": {"mcp_server"},
        "from .. import cli": {"cli"},
        "from ..api_v1 import handle_post": {"api_v1"},
        "def f():\n    from security_lakehouse.api_v1 import envelope\n": {"api_v1"},
        "class C:\n    def m(self):\n        import security_lakehouse.cli\n": {"cli"},
        "from security_lakehouse import api_contract, io": set(),
        "from security_lakehouse.api_v1_extra import x": set(),
        "from . import tokens": set(),
    }
    for source, expected in forms.items():
        assert entry_layer_edges(source, module) == expected, source


def test_scanner_finds_known_upper_layer_edge() -> None:
    server = PACKAGE_DIR / "server.py"
    assert "api_v1" in entry_layer_edges(server.read_text(encoding="utf-8"), f"{PACKAGE}.server")


def test_lower_layers_never_import_entry_layers() -> None:
    unexpected = sorted(edge for edge in _violations() if edge not in ALLOWED_EDGES)
    assert unexpected == [], f"lower layer imports an entry layer: {unexpected}"


def test_layering_allowlist_has_no_stale_entries() -> None:
    stale = sorted(edge for edge in ALLOWED_EDGES if edge not in _violations())
    assert stale == [], f"allowlisted edges no longer exist; remove them: {stale}"
    assert all(reason.strip() for reason in ALLOWED_EDGES.values())
