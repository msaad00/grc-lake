"""Run with an installed wheel interpreter outside the source checkout."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen


def main() -> None:
    import security_lakehouse
    from security_lakehouse.catalog import _data_root, load_control_catalog, validate_catalog

    expected = Path(sys.argv[1]).resolve()
    package = Path(security_lakehouse.__file__).resolve()
    assert package.is_relative_to(expected), (package, expected)
    assert _data_root().resolve().is_relative_to(expected), _data_root()
    assert load_control_catalog()
    assert not validate_catalog()
    with tempfile.TemporaryDirectory() as lake, socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
        reserved.close()
        # Exercise the installed runtime, without a test-client dependency that
        # is not part of the server extra.
        with tempfile.TemporaryFile() as log:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "security_lakehouse.cli",
                    "serve",
                    "--lake",
                    lake,
                    "--server",
                    "--allow-insecure-no-auth",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                ],
                stdout=log,
                stderr=log,
            )
            try:
                base = f"http://127.0.0.1:{port}"
                deadline = time.monotonic() + 30
                while True:
                    try:
                        with urlopen(base + "/api/v1/healthz", timeout=2) as response:
                            assert response.status == 200
                        break
                    except URLError:
                        if process.poll() is not None or time.monotonic() >= deadline:
                            log.seek(0)
                            raise RuntimeError(log.read().decode()) from None
                        time.sleep(0.1)
                with urlopen(base + "/console/", timeout=5) as response:
                    assert response.status == 200
                with urlopen(base + "/api/v1/snapshots/integrity", timeout=5) as response:
                    assert response.status == 200
                    assert json.load(response)["data"]["ok"] is True
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    print(json.dumps({"installed_package": "ok", "catalogs": "ok", "console": "ok", "integrity_route": "ok"}))


if __name__ == "__main__":
    main()
