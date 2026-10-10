"""Qualify an already-pulled image with authenticated, synthetic Compose traffic.

Uses the existing Compose server profile and readiness helper. No source package
is mounted into the container. Only the disposable volume is seeded; credentials
stay in memory and the temporary owner-only environment file is removed. This
local API-key probe does not qualify TLS, an IdP, providers, or production load.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import secrets
import shutil
import subprocess
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("compose_smoke", ROOT / "tools/compose_smoke.py")
_compose = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_compose)
run = _compose.run
wait_ready = _compose.wait_ready

# Executed by the image's interpreter against its installed package. Stdout is
# captured in memory only, never included in receipts or container logs.
SEED = """
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from security_lakehouse.db.base import create_engine_for, session_factory
from security_lakehouse.db.repository import create_tenant, create_user, create_api_key
from security_lakehouse.golden_fixture import build_golden_events
from security_lakehouse.pipeline import run_pipeline
root = Path('/lake')
engine = create_engine_for(root)
credentials = []
with session_factory(engine).begin() as session:
    for slug in ('probe-alpha', 'probe-beta'):
        tenant = create_tenant(session, slug=slug, name=slug)
        item = {'tenant': tenant.id, 'marker': slug, 'tokens': {}}
        for role in ('admin', 'read_only'):
            user = create_user(session, tenant_id=tenant.id,
                               email=role+'@'+slug+'.test', role=role)
            _, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id,
                                       expires_at=datetime.now(UTC)+timedelta(hours=1))
            item['tokens'][role] = token
        credentials.append(item)
for item in credentials:
    rows = build_golden_events(tenant_id=item['tenant'])
    for row in rows:
        row['entity']['asset_id'] = item['marker']+':'+row['entity']['asset_id']
        row['evidence']['evidence_id'] = item['marker']+':'+row['evidence']['evidence_id']
    raw = root / (item['marker']+'.jsonl')
    raw.write_text(''.join(json.dumps(row)+'\\n' for row in rows))
    run_pipeline(raw, root/'tenants'/item['tenant'], tenant_id=item['tenant'])
    raw.unlink()
engine.dispose()
print(json.dumps(credentials))
"""


def request(base, method, path, token=None, body=None, headers=None):
    request_headers = dict(headers or {})
    if token is not None:
        request_headers["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        request_headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method, headers=request_headers)
    try:
        response = urllib.request.urlopen(req, timeout=90)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        raw = response.read()
        payload = json.loads(raw) if "application/json" in response.headers.get("Content-Type", "") else raw
        return response.status, payload, response.headers


def expect(base, method, path, status, **kwargs):
    actual, payload, headers = request(base, method, path, **kwargs)
    assert actual == status, f"{method} {path}: expected {status}, got {actual}"
    return payload, headers


def assert_isolated(payload, own, other):
    encoded = json.dumps(payload)
    assert own in encoded, "own tenant evidence missing"
    assert other not in encoded, "cross-tenant evidence leaked"


def exercise(base, credentials):
    assert len(credentials) == 2 and len({c["tenant"] for c in credentials}) == 2, "need two distinct tenants"
    expect(base, "GET", "/api/v1/controls", 401)
    expect(base, "GET", "/api/v1/controls", 401, token="tops_invalid")
    snapshots = []
    for index, item in enumerate(credentials):
        admin, reader = item["tokens"]["admin"], item["tokens"]["read_only"]
        other = credentials[1 - index]
        identity, _ = expect(base, "GET", "/api/v1/auth/whoami", 200, token=reader)
        assert identity["data"]["tenant_id"] == item["tenant"]
        assert identity["data"]["scopes"] == ["read"]
        for suffix in ("", "?tenant_id=" + other["tenant"]):
            evidence, _ = expect(
                base, "GET", "/api/v1/evidence" + suffix, 200, token=reader, headers={"X-Tenant-ID": other["tenant"]}
            )
            if suffix:
                # A tenant_id filter may correctly return no rows. It must
                # never change the authenticated tenant or expose its neighbor.
                assert other["marker"] not in json.dumps(evidence), "cross-tenant evidence leaked"
            else:
                assert_isolated(evidence, item["marker"], other["marker"])
        expect(base, "POST", "/api/v1/snapshots", 403, token=reader, body={"reason": "denied"})
        expect(base, "GET", "/api/v1/auth/keys", 403, token=reader)
        created, _ = expect(base, "POST", "/api/v1/snapshots", 201, token=admin, body={"reason": item["marker"]})
        snapshots.append(created["data"])
        keys, _ = expect(
            base,
            "POST",
            "/api/v1/auth/keys",
            201,
            token=admin,
            body={
                "user_email": "admin@" + item["marker"] + ".test",
                "name": "revocation-probe",
                "expires_in_days": 1,
            },
        )
        key = keys["data"]
        assert key["expires_at"], "new probe key must expire"
        expect(base, "GET", "/api/v1/controls", 200, token=key["token"])
        expect(base, "DELETE", "/api/v1/auth/keys/" + key["id"], 404, token=other["tokens"]["admin"])
        expect(base, "GET", "/api/v1/controls", 200, token=key["token"])
        expect(base, "DELETE", "/api/v1/auth/keys/" + key["id"], 200, token=admin)
        expect(base, "GET", "/api/v1/controls", 401, token=key["token"])
        item["revoked_token"] = key["token"]
    return snapshots


def persistent_state(base, credentials):
    state = []
    for index, item in enumerate(credentials):
        token = item["tokens"]["admin"]
        expect(base, "GET", "/api/v1/controls", 401, token=item["revoked_token"])
        evidence, _ = expect(base, "GET", "/api/v1/evidence", 200, token=token)
        assert_isolated(evidence, item["marker"], credentials[1 - index]["marker"])
        snapshots, _ = expect(base, "GET", "/api/v1/snapshots", 200, token=token)
        assert snapshots["data"], "snapshot persistence missing"
        # Per-tenant markers prove lists did not accidentally read a shared lake.
        assert_isolated(snapshots, item["marker"], credentials[1 - index]["marker"])
        for snapshot in snapshots["data"]:
            snapshot_id = snapshot["snapshot_id"]
            expect(base, "GET", "/api/v1/snapshots/" + snapshot_id, 200, token=token)
            expect(
                base, "GET", "/api/v1/snapshots/" + snapshot_id, 404, token=credentials[1 - index]["tokens"]["admin"]
            )
            expect(
                base,
                "GET",
                "/api/v1/snapshots/" + snapshot_id + "/export.pdf",
                404,
                token=credentials[1 - index]["tokens"]["admin"],
            )
        integrity, _ = expect(base, "GET", "/api/v1/snapshots/integrity", 200, token=token)
        assert integrity["data"]["ok"] is True
        state.append(
            {
                "tenant": item["tenant"],
                "evidence": evidence["data"],
                "snapshots": snapshots["data"],
                "integrity": integrity["data"],
            }
        )
    return state


def qualify(image: str, output: Path, platform: str | None = None):
    output.mkdir(parents=True, exist_ok=False)
    project = "grc-lake-auth-" + uuid.uuid4().hex[:12]
    (output / "project-name.txt").write_text(project + "\n")
    shutil.copyfile(ROOT / "compose.yaml", output / "compose.yaml")
    override = (
        "services:\n  grc-lake-server:\n"
        f"    image: {json.dumps(image)}\n"
        '    ports: !override\n      - "127.0.0.1::8787"\n'
    )
    if platform:
        override += f"    platform: {json.dumps(platform)}\n"
    override += (
        f"volumes:\n  grc-lake-lake:\n    name: {project}-server\n  grc-lake-demo-lake:\n    name: {project}-demo\n"
    )
    (output / "override.yaml").write_text(override)
    env_file = output / "grc-lake.env"
    with os.fdopen(os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        stream.write("GRC_LAKE_COOKIE_SIGNING_KEY=" + secrets.token_hex(32) + "\n")
    compose = [
        "docker",
        "compose",
        "-p",
        project,
        "-f",
        str(output / "compose.yaml"),
        "-f",
        str(output / "override.yaml"),
        "--profile",
        "server",
    ]
    receipt = {
        "image": image,
        "platform": platform,
        "project": project,
        "ok": False,
        "boundary": "local synthetic API-key qualification; no TLS, IdP, provider or capacity proof",
    }
    try:
        run(*compose, "config", "--quiet")
        up = [*compose, "up", "-d", "--no-build", "--pull", "never"]
        run(*up, "grc-lake-server")

        def instance():
            address = run(*compose, "port", "grc-lake-server", "8787")
            assert address.startswith("127.0.0.1:")
            base = "http://" + address
            wait_ready(base, timeout=180)
            container = run(*compose, "ps", "-q", "grc-lake-server")
            info = json.loads(run("docker", "inspect", container))[0]
            assert info["Config"]["Image"] == image
            runtime = json.loads(
                run(
                    *compose,
                    "exec",
                    "-T",
                    "grc-lake-server",
                    "python",
                    "-c",
                    "import os,platform,json; from importlib.metadata import version; "
                    'print(json.dumps(dict(uid=os.getuid(),machine=platform.machine(),version=version("grc-lake"))))',
                )
            )
            assert runtime["uid"] != 0
            if platform:
                assert runtime["machine"] == {"linux/amd64": "x86_64", "linux/arm64": "aarch64"}[platform]
            page, _ = expect(base, "GET", "/console/dashboard/", 200)
            assert b"<html" in page
            receipt.update(image_id=info["Image"], runtime=runtime)
            return base, container

        base, first = instance()
        credentials = json.loads(run(*compose, "exec", "-T", "grc-lake-server", "python", "-c", SEED, timeout=300))
        exercise(base, credentials)
        before = persistent_state(base, credentials)
        run(*up, "--force-recreate", "grc-lake-server")
        base, second = instance()
        assert first != second
        assert persistent_state(base, credentials) == before, "state changed across container recreation"
        receipt.update(
            ok=True,
            checks=[
                "missing-and-invalid-key-denied",
                "reader-write-denied",
                "two-tenant-evidence-isolation",
                "tenant-header-and-query-cannot-switch-identity",
                "cross-tenant-key-revocation-denied",
                "key-revocation-enforced",
                "snapshot-detail-and-export-isolation",
                "authenticated-persistence-after-recreation",
                "snapshot-chain-integrity",
                "non-root",
                "bundled-console",
            ],
            tenants=2,
        )
    finally:
        # Keep the primary failure visible even if the daemon died. Receipts
        # explicitly distinguish a failed cleanup from removed resources.
        try:
            (output / "container.log").write_text(run(*compose, "logs", "--no-color") + "\n")
        except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
            receipt["log_collection_error"] = type(exc).__name__
        try:
            run(*compose, "down", "--volumes")
            receipt["cleanup"] = "containers and disposable volume removed"
        except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
            receipt["cleanup"] = "failed; remove this project when Docker is available"
            receipt["cleanup_error"] = type(exc).__name__
            receipt["ok"] = False
        finally:
            env_file.unlink(missing_ok=True)
            (output / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if not receipt["ok"]:
        raise RuntimeError("qualification cleanup failed; see result.json")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="grc-lake:ci")
    parser.add_argument("--platform", choices=["linux/amd64", "linux/arm64"])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    qualify(args.image, args.output.resolve(), args.platform)
    print("Authenticated authorization, tenant isolation and recreation checks passed.")


if __name__ == "__main__":
    main()
