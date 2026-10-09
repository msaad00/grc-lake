"""Qualify a built image against disposable PostgreSQL and real SeaweedFS S3.

Uses an isolated Docker network with no host ports. Always removes only its own
uniquely named Compose project and volumes. Reports never contain credentials.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy/examples/distributed/qualification/compose.yaml"


def qualify(image: str, output: Path) -> None:
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    project = "grc-qualification-" + uuid.uuid4().hex[:12]
    (output / "project-name.txt").write_text(project + "\n")
    image_id = subprocess.check_output(["docker", "image", "inspect", image, "--format", "{{.Id}}"], text=True).strip()
    env = {
        **os.environ,
        "GRC_QUAL_IMAGE": image,
        "GRC_QUAL_WORK": str(output),
        "GRC_QUAL_PASSWORD": secrets.token_hex(24),
        "GRC_QUAL_SIGNING_KEY": secrets.token_hex(32),
        "GRC_QUAL_S3_SECRET": secrets.token_hex(24),
        "GRC_QUAL_UID": str(os.getuid()),
        "GRC_QUAL_GID": str(os.getgid()),
    }
    config = output / "s3.json"
    config.write_text(
        json.dumps(
            {
                "identities": [
                    {
                        "name": "qualification",
                        "credentials": [{"accessKey": "qualification", "secretKey": env["GRC_QUAL_S3_SECRET"]}],
                        "actions": ["Admin", "Read", "Write", "List", "Tagging"],
                    }
                ]
            }
        )
    )
    config.chmod(0o600)
    command = ["docker", "compose", "--project-name", project, "-f", str(COMPOSE)]

    def compose(*args, timeout=180):
        result = subprocess.run([*command, *args], env=env, capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            diagnostics = result.stdout + result.stderr
            protected = [env["GRC_QUAL_PASSWORD"], env["GRC_QUAL_SIGNING_KEY"], env["GRC_QUAL_S3_SECRET"]]
            credentials = output / "credentials.json"
            if credentials.exists():
                protected.extend(item["token"] for item in json.loads(credentials.read_text()))
            for secret in protected:
                diagnostics = diagnostics.replace(secret, "[REDACTED]")
            (output / "failure.log").write_text(diagnostics[-32768:])
            raise RuntimeError(f"Compose {' '.join(args[:3])} failed with exit {result.returncode}")
        return result.stdout.strip()

    def probe(phase, timeout=240):
        print(f"Qualification: {phase}", flush=True)
        compose("run", "--rm", "--no-deps", "probe", phase, timeout=timeout)

    try:
        compose("up", "-d", "postgres", "s3")
        probe("prepare")
        assignments = json.loads((output / "prepare.json").read_text())["worker_shards"]
        env["GRC_QUAL_SHARDS_A"], env["GRC_QUAL_SHARDS_B"] = assignments
        compose("up", "-d", "api-a", "api-b", "reader")
        probe("enqueue")
        compose("up", "-d", "worker-a", "worker-b")
        probe("verify")
        # Delete only this project's replica scratch; durable stores stay intact.
        container = compose("ps", "-q", "api-b")
        mounts = json.loads(subprocess.check_output(["docker", "inspect", container], text=True))[0]["Mounts"]
        volume = next(m["Name"] for m in mounts if m["Destination"] == "/lake")
        if not volume.startswith(project + "_"):
            raise RuntimeError("refusing to remove a volume outside this qualification project")
        compose("rm", "-s", "-f", "api-b")
        subprocess.run(["docker", "volume", "rm", volume], check=True, capture_output=True, timeout=30)
        compose("up", "-d", "api-b")
        probe("cold-restart")
        compose("stop", "s3")
        probe("object-outage")
        compose("start", "s3")
        probe("objects-recovered")
        compose("stop", "postgres")
        probe("database-outage")
        compose("start", "postgres")
        probe("database-recovered")
        compose("up", "-d", "crash-writer")
        deadline = time.monotonic() + 60
        while not (output / "writer-held.json").exists():
            if time.monotonic() > deadline:
                raise RuntimeError("crash writer did not acquire its lease")
            time.sleep(0.5)
        compose("kill", "-s", "SIGKILL", "crash-writer")
        probe("crash-recovery", timeout=240)
        compose("kill", "-s", "SIGKILL", "worker-a")
        compose("up", "-d", "worker-a")
        probe("enqueue")
        probe("verify")
        report = {
            "passed": True,
            "application_image": image,
            "application_image_id": image_id,
            "checks": {
                p.stem: json.loads(p.read_text())
                for p in output.glob("*.json")
                if p.name not in {"s3.json", "credentials.json", "report.json"}
            },
            "limitations": [
                "single Docker host",
                "single PostgreSQL primary",
                "single SeaweedFS server",
                "synthetic evidence",
                "not a storage-replication or production-capacity certification",
            ],
        }
        (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(f"Qualification passed: {output / 'report.json'}", flush=True)
    finally:
        try:
            compose("down", "--volumes", "--remove-orphans", timeout=90)
        finally:
            config.unlink(missing_ok=True)
            (output / "credentials.json").unlink(missing_ok=True)


def cleanup(output: Path) -> None:
    marker = output / "project-name.txt"
    if not marker.exists():
        return
    project = marker.read_text().strip()
    if re.fullmatch(r"grc-qualification-[0-9a-f]{12}", project) is None:
        raise ValueError("invalid qualification project marker")
    env = {
        **os.environ,
        "GRC_QUAL_IMAGE": "grc-lake:cleanup",
        "GRC_QUAL_WORK": str(output.resolve()),
        "GRC_QUAL_PASSWORD": "cleanup-unused",
        "GRC_QUAL_SIGNING_KEY": "cleanup-unused",
        "GRC_QUAL_S3_SECRET": "cleanup-unused",
    }
    subprocess.run(
        ["docker", "compose", "--project-name", project, "-f", str(COMPOSE), "down", "--volumes", "--remove-orphans"],
        env=env,
        check=True,
        timeout=90,
    )
    (output / "s3.json").unlink(missing_ok=True)
    (output / "credentials.json").unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", help="already-built local GRC Lake image")
    parser.add_argument("--out", type=Path, required=True, help="new directory for sanitized reports")
    parser.add_argument("--cleanup", action="store_true", help="remove only the project recorded by this run")
    args = parser.parse_args()
    if args.cleanup:
        cleanup(args.out)
    elif args.image:
        qualify(args.image, args.out)
    else:
        parser.error("--image is required unless --cleanup is selected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
