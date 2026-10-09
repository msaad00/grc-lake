"""The imported wheel must find its own user-scheme catalogs."""

import sysconfig

import pytest

from security_lakehouse import catalog


def test_user_install_wins_over_unrelated_prefix_catalogs(tmp_path, monkeypatch):
    user = tmp_path / "user-data"
    userlib = tmp_path / "user-packages"
    prefix = tmp_path / "other-install"
    for root in (user, prefix):
        for name in ("controls", "connectors"):
            path = root / name / "catalog.json"
            path.parent.mkdir(parents=True)
            path.write_text("{}")
    monkeypatch.delenv("GRC_LAKE_DATA_DIR", raising=False)
    monkeypatch.setattr(catalog, "__file__", str(userlib / "security_lakehouse/catalog.py"))
    monkeypatch.setattr(catalog.sys, "prefix", str(prefix))
    monkeypatch.setattr(catalog.sys, "base_prefix", str(prefix))
    monkeypatch.setattr(sysconfig, "get_path", lambda name, scheme=None: str(user if name == "data" else userlib))
    assert catalog._data_root() == user
    # A damaged user install must not silently borrow another version's catalogs.
    (user / "controls/catalog.json").unlink()
    assert catalog._data_root() == user
    monkeypatch.setenv("GRC_LAKE_DATA_DIR", str(tmp_path / "explicit"))
    assert catalog._data_root() == tmp_path / "explicit"


def test_non_user_install_ignores_user_catalogs(tmp_path, monkeypatch):
    prefix = tmp_path / "venv"
    for name in ("controls", "connectors"):
        path = prefix / name / "catalog.json"
        path.parent.mkdir(parents=True)
        path.write_text("{}")
    monkeypatch.delenv("GRC_LAKE_DATA_DIR", raising=False)
    monkeypatch.setattr(catalog, "__file__", str(_installed_module(prefix)))
    monkeypatch.setattr(catalog.sys, "prefix", str(prefix))
    monkeypatch.setattr(sysconfig, "get_path", lambda name, scheme=None: str(tmp_path / "unrelated-user"))
    assert catalog._data_root() == prefix


def _catalogs(root):
    for name in ("controls", "connectors"):
        path = root / name / "catalog.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}")


def _installed_module(prefix):
    from pathlib import Path

    paths = sysconfig.get_paths(vars={"base": str(prefix), "platbase": str(prefix)})
    return Path(paths["purelib"]) / "security_lakehouse/catalog.py"


@pytest.mark.parametrize("origin", ["venv", "base"])
@pytest.mark.parametrize("damaged", [False, True])
def test_catalogs_follow_imported_installation_not_available_other_prefix(tmp_path, monkeypatch, origin, damaged):
    prefixes = {"venv": tmp_path / "venv", "base": tmp_path / "base"}
    for prefix in prefixes.values():
        _catalogs(prefix)
    own = prefixes[origin]
    if damaged:
        (own / "controls/catalog.json").unlink()
    monkeypatch.delenv("GRC_LAKE_DATA_DIR", raising=False)
    monkeypatch.setattr(catalog, "__file__", str(_installed_module(own)))
    monkeypatch.setattr(catalog.sys, "prefix", str(prefixes["venv"]))
    monkeypatch.setattr(catalog.sys, "base_prefix", str(prefixes["base"]))
    # A system package visible through --system-site-packages still owns its
    # system catalogs; a damaged venv must not borrow those same catalogs.
    assert catalog._data_root() == own


@pytest.mark.parametrize("damaged", [False, True])
def test_editable_checkout_keeps_own_data_even_inside_prefix(tmp_path, monkeypatch, damaged):
    prefix = tmp_path / "venv"
    checkout = prefix / "projects/trustops"
    _catalogs(prefix)
    _catalogs(checkout)
    if damaged:
        (checkout / "controls/catalog.json").unlink()
    monkeypatch.delenv("GRC_LAKE_DATA_DIR", raising=False)
    monkeypatch.setattr(catalog, "__file__", str(checkout / "src/security_lakehouse/catalog.py"))
    monkeypatch.setattr(catalog.sys, "prefix", str(prefix))
    assert catalog._data_root() == checkout
