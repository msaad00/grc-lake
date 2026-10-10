"""Release bundles survive runner deletion and attestation API unavailability."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _jobs() -> dict:
    return yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())["jobs"]


def test_python_bundle_is_retained_before_publication_and_attached_to_release() -> None:
    jobs = _jobs()
    steps = jobs["pypi"]["steps"]
    attest = next(step for step in steps if step.get("uses", "").startswith("actions/attest@"))
    assert attest.get("id"), "Attestation output must be addressable for retention"
    stage = next(step for step in steps if step.get("name") == "Stage Python provenance bundle")
    assert stage["env"]["BUNDLE_PATH"] == "${{ steps." + attest["id"] + ".outputs.bundle-path }}"
    upload = next(step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert upload["with"]["name"] == "python-provenance"
    assert upload["with"]["path"] == "provenance/python-provenance.sigstore.json"
    assert upload["with"]["if-no-files-found"] == "error"
    publish = next(step for step in steps if step.get("uses", "").startswith("pypa/gh-action-pypi-publish@"))
    assert steps.index(attest) < steps.index(stage) < steps.index(upload) < steps.index(publish)
    # Bundles must not land in the directory uploaded to PyPI as distributions.
    assert attest["with"]["subject-path"] == "dist/*"
    release_steps = jobs["github-release"]["steps"]
    download = next(step for step in release_steps if step.get("with", {}).get("name") == "python-provenance")
    assert download["uses"].startswith("actions/download-artifact@")
    assert download["with"]["path"] == "provenance"
    release = next(step for step in release_steps if step.get("uses", "").startswith("softprops/action-gh-release@"))
    assert release_steps.index(download) < release_steps.index(release)
    assert "provenance/python-provenance.sigstore.json" in release["with"]["files"].splitlines()
    assert release["with"]["fail_on_unmatched_files"] is True
    assert "pypi" in jobs["github-release"]["needs"]
    for step in (stage, upload, download):
        assert not step.get("continue-on-error")
        assert "if" not in step


@pytest.mark.parametrize("bundle_state", ["present", "empty", "missing"])
def test_bundle_staging_preserves_bytes_and_rejects_missing_evidence(tmp_path: Path, bundle_state: str) -> None:
    steps = _jobs()["pypi"]["steps"]
    stage = next(step for step in steps if step.get("name") == "Stage Python provenance bundle")
    source = tmp_path / "runner bundle.json"
    payload = b'{"fixture": "signed bundle bytes are copied unchanged"}\n'
    if bundle_state != "missing":
        source.write_bytes(payload if bundle_state == "present" else b"")
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", stage["run"]],
        cwd=tmp_path,
        env={**os.environ, "BUNDLE_PATH": str(source)},
        capture_output=True,
        check=False,
    )
    target = tmp_path / "provenance/python-provenance.sigstore.json"
    if bundle_state == "present":
        assert result.returncode == 0, result.stderr
        assert target.read_bytes() == payload
    else:
        assert result.returncode != 0
        assert not target.exists()
