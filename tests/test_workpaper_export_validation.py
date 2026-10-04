"""Malformed portable manifests retain the CLI verification result contract."""

import json
import subprocess
import sys

import pytest


@pytest.mark.parametrize("files", [["index.html", "workpaper.json"], None, "index.html", {}])
def test_malformed_file_table_returns_structured_failure(tmp_path, files):
    (tmp_path / "manifest.json").write_text(
        json.dumps({"schema_version": "trustops.workpaper_export.v1", "files": files})
    )
    result = subprocess.run(
        [sys.executable, "-m", "security_lakehouse.cli", "assessment", "verify-workpaper", "--dir", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "ok": False,
        "authentication": "hash_consistency_only; review identity requires server record",
    }
