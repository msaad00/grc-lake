"""Run with an installed wheel interpreter outside the source checkout."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path


def main() -> None:
    from fastapi.testclient import TestClient

    import security_lakehouse
    from security_lakehouse.catalog import _data_root, load_control_catalog, validate_catalog
    from security_lakehouse.server_app import create_app

    expected = Path(sys.argv[1]).resolve()
    package = Path(security_lakehouse.__file__).resolve()
    assert package.is_relative_to(expected), (package, expected)
    assert _data_root().resolve().is_relative_to(expected), _data_root()
    assert load_control_catalog()
    assert not validate_catalog()
    with tempfile.TemporaryDirectory() as lake:
        client = TestClient(create_app(lake, require_auth=False))
        assert client.get("/api/v1/healthz").status_code == 200
        assert client.get("/console/").status_code == 200
        integrity = client.get("/api/v1/snapshots/integrity")
        assert integrity.status_code == 200
        assert integrity.json()["data"]["ok"] is True
    print(json.dumps({"installed_package": "ok", "catalogs": "ok", "console": "ok", "integrity_route": "ok"}))


if __name__ == "__main__":
    main()
