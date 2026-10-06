"""The imported wheel must find its own user-scheme catalogs."""

import sysconfig

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
    monkeypatch.delenv("TRUSTOPS_DATA_DIR", raising=False)
    monkeypatch.setattr(catalog, "__file__", str(userlib / "security_lakehouse/catalog.py"))
    monkeypatch.setattr(catalog.sys, "prefix", str(prefix))
    monkeypatch.setattr(catalog.sys, "base_prefix", str(prefix))
    monkeypatch.setattr(sysconfig, "get_path", lambda name, scheme=None: str(user if name == "data" else userlib))
    assert catalog._data_root() == user
    # A damaged user install must not silently borrow another version's catalogs.
    (user / "controls/catalog.json").unlink()
    assert catalog._data_root() == user
    monkeypatch.setenv("TRUSTOPS_DATA_DIR", str(tmp_path / "explicit"))
    assert catalog._data_root() == tmp_path / "explicit"


def test_non_user_install_ignores_user_catalogs(tmp_path, monkeypatch):
    prefix = tmp_path / "venv"
    for name in ("controls", "connectors"):
        path = prefix / name / "catalog.json"
        path.parent.mkdir(parents=True)
        path.write_text("{}")
    monkeypatch.delenv("TRUSTOPS_DATA_DIR", raising=False)
    monkeypatch.setattr(catalog, "__file__", str(prefix / "lib/python3.13/site-packages/security_lakehouse/catalog.py"))
    monkeypatch.setattr(catalog.sys, "prefix", str(prefix))
    monkeypatch.setattr(sysconfig, "get_path", lambda name, scheme=None: str(tmp_path / "unrelated-user"))
    assert catalog._data_root() == prefix
