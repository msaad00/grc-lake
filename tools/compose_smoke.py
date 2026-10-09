"""Exercise the documented Compose quickstart using an already-built local image.

Requires Docker Compose >= 2.24.4 (!override). Uses a unique project, a fresh
named volume, and a dynamically assigned loopback port. No registry pull occurs.
Only synthetic demo data is loaded; the authenticated profile is config-checked.
"""

from __future__ import annotations

import argparse
import json
import secrets
import shutil
import subprocess
import time
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKPOINT = """
import hashlib, json, os
from pathlib import Path
lake = Path('/lake')
marker = lake / '.grc-lake-demo-seeded'
assert marker.is_file(), 'demo seed marker missing'
print(json.dumps({
    'marker_mtime_ns': marker.stat().st_mtime_ns,
    'manifest_sha256': hashlib.sha256((lake / 'manifest.json').read_bytes()).hexdigest(),
    'uid': os.getuid(),
}))
"""


def run(*args: str, timeout: int = 60) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout).stdout.strip()


def get(base: str, path: str) -> bytes:
    with urllib.request.urlopen(base + path, timeout=3) as response:
        assert response.status == 200, f"{path}: HTTP {response.status}"
        return response.read()


def wait_ready(base: str, timeout: float = 90) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            if json.loads(get(base, "/api/readyz")).get("ok") is True:
                return
        except (OSError, json.JSONDecodeError) as exc:
            last_error = exc
        time.sleep(0.5)
    if last_error is not None:
        raise RuntimeError(f"Compose demo did not become ready before the deadline (last error: {last_error})")
    raise RuntimeError("Compose demo did not become ready before the deadline")


def check_http(base: str) -> dict:
    assert json.loads(get(base, "/api/healthz"))["ok"] is True
    assert b"<html" in get(base, "/console/dashboard/")
    posture = json.loads(get(base, "/api/v1/posture/current"))
    assert posture["data"]["posture"]["state"] == "critical", "golden fixture posture is not critical"
    return posture["data"]["posture"]


def qualify(image: str, output: Path) -> None:
    # Never overwrite another run's diagnostics or reuse its volume.
    output.mkdir(parents=True, exist_ok=False)
    project = "grc-lake-smoke-" + uuid.uuid4().hex[:12]
    (output / "project-name.txt").write_text(project + "\n")
    shutil.copyfile(ROOT / "compose.yaml", output / "compose.yaml")
    (output / "override.yaml").write_text(
        "services:\n  grc-lake:\n"
        f"    image: {json.dumps(image)}\n"
        '    ports: !override\n      - "127.0.0.1::8787"\n'
        "  grc-lake-server:\n"
        f"    image: {json.dumps(image)}\n"
        "volumes:\n  grc-lake-demo-lake:\n"
        f"    name: {project}-demo\n"
        "  grc-lake-lake:\n"
        f"    name: {project}-server\n"
    )
    env_file = output / "grc-lake.env"
    example = (ROOT / "deploy/compose/grc-lake.env.example").read_text()
    example = example.replace(
        "GRC_LAKE_COOKIE_SIGNING_KEY=\n", f"GRC_LAKE_COOKIE_SIGNING_KEY={secrets.token_hex(32)}\n"
    )
    example = example.replace("GRC_LAKE_PUBLIC_URL=\n", "GRC_LAKE_PUBLIC_URL=https://grc-lake.example.test\n")
    env_file.write_text(example)
    env_file.chmod(0o600)
    compose = [
        "docker",
        "compose",
        "-p",
        project,
        "-f",
        str(output / "compose.yaml"),
        "-f",
        str(output / "override.yaml"),
    ]
    receipt: dict = {"image": image, "project": project, "ok": False}
    try:
        expected_image = run("docker", "image", "inspect", image, "--format", "{{.Id}}")
        run(*compose, "--profile", "server", "config", "--quiet")
        up = [*compose, "up", "-d", "--no-build", "--pull", "never", "grc-lake"]
        run(*up)

        def inspect_instance() -> tuple[str, dict, dict]:
            address = run(*compose, "port", "grc-lake", "8787")
            assert address.startswith("127.0.0.1:"), "demo must bind only to loopback"
            base = "http://" + address
            wait_ready(base)
            container = run(*compose, "ps", "-q", "grc-lake")
            assert run("docker", "inspect", container, "--format", "{{.Image}}") == expected_image
            checkpoint = json.loads(run(*compose, "exec", "-T", "grc-lake", "python", "-c", CHECKPOINT))
            assert checkpoint["uid"] != 0, "demo must run as a non-root user"
            return container, checkpoint, check_http(base)

        first_container, first_checkpoint, first_posture = inspect_instance()
        # Recreate the process while keeping the volume. A bare second `up`
        # leaves the container running and would never exercise the seed guard.
        run(*compose, "up", "-d", "--no-build", "--pull", "never", "--force-recreate", "grc-lake")
        second_container, second_checkpoint, second_posture = inspect_instance()
        assert first_container != second_container, "container was not recreated"
        assert second_checkpoint == first_checkpoint, "demo was reseeded or its manifest changed"
        assert second_posture == first_posture, "posture changed across container recreation"
        run(*compose, "exec", "-T", "grc-lake", "grc-lake", "pipeline", "verify-integrity", "--lake", "/lake")
        receipt.update(
            ok=True,
            image_id=expected_image,
            checkpoint=second_checkpoint,
            checks=[
                "server-profile-config",
                "local-built-image",
                "loopback-only",
                "readiness",
                "health",
                "bundled-console",
                "golden-posture",
                "non-root",
                "recreate-without-reseed",
                "integrity",
            ],
        )
    finally:
        (output / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
        try:
            logs = run(*compose, "logs", "--no-color")
            (output / "container.log").write_text(logs + "\n")
        finally:
            try:
                run(*compose, "down", "--volumes")
            finally:
                env_file.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="grc-lake:ci")
    parser.add_argument("--output", type=Path, default=ROOT / "build/compose-smoke")
    args = parser.parse_args()
    qualify(args.image, args.output.resolve())
    print("Compose startup, golden posture, recreation and integrity checks passed.")


if __name__ == "__main__":
    main()
