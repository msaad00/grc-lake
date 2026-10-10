"""Replay the fuzz targets' seed corpora so their invariants run in every test pass.

The coverage-guided runs live in ClusterFuzzLite; this keeps the targets
importable, their seeds meaningful, and fixed crashes fixed without atheris.
"""

from __future__ import annotations

import importlib
import random
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
FUZZ = ROOT / "fuzz"
TARGETS = sorted(path.stem for path in FUZZ.glob("fuzz_*.py"))


@pytest.fixture
def target(request: pytest.FixtureRequest) -> Iterator[Callable[[bytes], None]]:
    sys.path.insert(0, str(FUZZ))
    try:
        yield importlib.import_module(request.param).TestOneInput
    finally:
        sys.path.remove(str(FUZZ))


def test_every_target_has_a_seed_corpus() -> None:
    assert TARGETS == ["fuzz_aibom_import", "fuzz_raw_evidence", "fuzz_strict_json", "fuzz_webhook_signatures"]
    for name in TARGETS:
        assert any((FUZZ / "corpus" / name).iterdir()), name


@pytest.mark.parametrize("target", TARGETS, indirect=True)
def test_seed_corpus_and_random_inputs_hold_invariants(target: Callable[[bytes], None]) -> None:
    name = target.__module__
    for seed in sorted((FUZZ / "corpus" / name).iterdir()):
        target(seed.read_bytes())
    rng = random.Random(name)
    for _ in range(300):
        target(rng.randbytes(rng.randrange(0, 256)))


@pytest.mark.parametrize(
    ("target", "data"),
    [
        # Stripe header "t=²,v1=00": str.isdigit() accepted, int() raised.
        ("fuzz_webhook_signatures", b"\x01\x00\x00\x00" + bytes([18]) + "t=²,v1=00".encode("utf-16-le")),
        # Receiver signature "é": hmac.compare_digest() raised TypeError.
        ("fuzz_webhook_signatures", b"\x00\x00\x00\x02" + "é".encode("utf-16-le")),
        (
            "fuzz_aibom_import",
            b'\x01{"bomFormat":"CycloneDX","specVersion":"1.6",'
            b'"components":[{"type":"library","name":"x","externalReferences":5}]}',
        ),
        (
            "fuzz_aibom_import",
            b'\x01{"@context":"spdx","@graph":[{"type":"software_Package","name":"p","spdxId":"spdx:a"},'
            b'{"type":"Relationship","relationshipType":["x"]}]}',
        ),
    ],
    indirect=["target"],
)
def test_fixed_crashes_stay_fixed(target: Callable[[bytes], None], data: bytes) -> None:
    target(data)


def test_clusterfuzzlite_builds_every_target_with_its_seed_corpus() -> None:
    project = yaml.safe_load((ROOT / ".clusterfuzzlite/project.yaml").read_text())
    assert project == {"language": "python"}
    dockerfile = (ROOT / ".clusterfuzzlite/Dockerfile").read_text()
    assert "FROM gcr.io/oss-fuzz-base/base-builder-python:v1@sha256:" in dockerfile
    build = (ROOT / ".clusterfuzzlite/build.sh").read_text()
    assert "compile_python_fuzzer" in build and "fuzz/fuzz_*.py" in build and "_seed_corpus.zip" in build


@pytest.mark.parametrize(("workflow", "mode"), [("cflite_pr.yml", "code-change"), ("cflite_batch.yml", "batch")])
def test_clusterfuzzlite_workflows_are_pinned_and_least_privilege(workflow: str, mode: str) -> None:
    text = (ROOT / ".github/workflows" / workflow).read_text()
    parsed = yaml.safe_load(text)
    assert parsed["permissions"] == "read-all"
    steps = [step for job in parsed["jobs"].values() for step in job["steps"]]
    uses = [step["uses"] for step in steps if "uses" in step]
    assert any(use.startswith("google/clusterfuzzlite/actions/build_fuzzers@") for use in uses)
    for use in uses:
        _, _, ref = use.partition("@")
        assert len(ref) == 40 and all(char in "0123456789abcdef" for char in ref), use
    run = next(step for step in steps if step.get("uses", "").startswith("google/clusterfuzzlite/actions/run_fuzzers"))
    assert run["with"]["language"] == "python" and run["with"]["mode"] == mode
    assert "storage-repo" not in run["with"]
    for job in parsed["jobs"].values():
        granted = job.get("permissions", {})
        assert set(granted) <= {"actions", "contents", "security-events"}
        assert all(granted[scope] == "read" for scope in granted if scope != "security-events")
        if "security-events" in granted:
            assert any("upload-sarif" in use for use in uses)
