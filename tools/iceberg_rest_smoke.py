"""Synthetic Polaris REST + independent DuckDB snapshot compatibility check.

Runs one disposable loopback-only Polaris container with a local FILE warehouse.
Test credentials are generated in memory, never printed or written to reports,
then destroyed with the container. This is not a cloud storage/deployment test.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
import time
from pathlib import Path
from uuid import uuid4

import duckdb
import requests
from pyiceberg.exceptions import ForbiddenError

from security_lakehouse.iceberg_export import publish_iceberg, rest_catalog
from security_lakehouse.io import read_jsonl, write_jsonl
from security_lakehouse.pipeline import run_pipeline

POLARIS_IMAGE = "apache/polaris:1.7.0@sha256:3495f67f38cca33892a045f7dd3f46eb52387f0fd52d4145538a772fd8aedad7"
ROOT = Path(__file__).resolve().parents[1]


def run():
    name = "trustops-iceberg-" + uuid4().hex[:12]
    bootstrap = secrets.token_urlsafe(32)
    environment = {**os.environ, "POLARIS_BOOTSTRAP_CREDENTIALS": f"POLARIS,root,{bootstrap}"}
    session = requests.Session()
    session.trust_env = False
    report = {"kind": "synthetic-local-polaris-proof", "polaris_image": POLARIS_IMAGE, "cloud_storage_tested": False}

    def docker(*args):
        result = subprocess.run(["docker", *args], env=environment, capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise RuntimeError("local Polaris container operation failed")
        return result.stdout.strip()

    with tempfile.TemporaryDirectory(prefix="trustops-polaris-", dir="/tmp") as directory:
        root = Path(directory).resolve()
        root.chmod(0o755)
        warehouse = root / "warehouse"
        warehouse.mkdir(mode=0o777)
        warehouse.chmod(0o777)  # Synthetic shared FILE warehouse for the container UID.
        previous_umask = os.umask(0o002)
        try:
            docker(
                "run",
                "-d",
                "--name",
                name,
                # Both processes write the synthetic FILE warehouse. Preserve
                # the image's named user (required by Hadoop) and share the
                # runner's group; the temporary umask makes directories writable.
                "--group-add",
                str(os.getgid()),
                "-p",
                "127.0.0.1::8181",
                "-p",
                "127.0.0.1::8182",
                "-v",
                f"{warehouse}:{warehouse}",
                "-e",
                "POLARIS_BOOTSTRAP_CREDENTIALS",
                "-e",
                "polaris.realm-context.realms=POLARIS",
                "-e",
                "quarkus.otel.sdk.disabled=true",
                "-e",
                'polaris.features."ALLOW_INSECURE_STORAGE_TYPES"=true',
                "-e",
                'polaris.features."SUPPORTED_CATALOG_STORAGE_TYPES"=["FILE"]',
                "-e",
                "polaris.readiness.ignore-severe-issues=true",
                POLARIS_IMAGE,
            )
            port = docker("port", name, "8181/tcp").rsplit(":", 1)[1]
            health_port = docker("port", name, "8182/tcp").rsplit(":", 1)[1]
            base = f"http://127.0.0.1:{port}"
            for _ in range(120):
                try:
                    if session.get(f"http://127.0.0.1:{health_port}/q/health", timeout=2).status_code == 200:
                        break
                except requests.RequestException:
                    # Connection refusal is expected while Polaris starts.
                    pass
                time.sleep(0.5)
            else:
                raise RuntimeError("local Polaris health check timed out")

            def token(client_id, client_secret):
                response = session.post(
                    base + "/api/catalog/v1/oauth/tokens",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "scope": "PRINCIPAL_ROLE:ALL",
                    },
                    timeout=15,
                )
                if response.status_code != 200:
                    raise RuntimeError("test token issuance failed")
                return response.json()["access_token"]

            admin_token = token("root", bootstrap)

            def management(method, path, payload):
                response = session.request(
                    method,
                    base + "/api/management/v1" + path,
                    headers={"Authorization": "Bearer " + admin_token},
                    json=payload,
                    timeout=15,
                )
                if response.status_code not in (200, 201, 204):
                    raise RuntimeError(f"test catalog setup failed: {method} {path} ({response.status_code})")
                return response.json() if response.content else {}

            for suffix in ("a", "b"):
                location = warehouse / suffix
                location.mkdir()
                management(
                    "POST",
                    "/catalogs",
                    {
                        "catalog": {
                            "name": "tenant_" + suffix,
                            "type": "INTERNAL",
                            "readOnly": False,
                            "properties": {"default-base-location": location.as_uri()},
                            "storageConfigInfo": {"storageType": "FILE", "allowedLocations": [location.as_uri()]},
                        }
                    },
                )
            credentials = management("POST", "/principals", {"principal": {"name": "writer_a", "properties": {}}})[
                "credentials"
            ]
            management("POST", "/principal-roles", {"principalRole": {"name": "writer_a_role", "properties": {}}})
            management(
                "POST",
                "/catalogs/tenant_a/catalog-roles",
                {"catalogRole": {"name": "writer_a_catalog", "properties": {}}},
            )
            management("PUT", "/principals/writer_a/principal-roles", {"principalRole": {"name": "writer_a_role"}})
            management(
                "PUT",
                "/principal-roles/writer_a_role/catalog-roles/tenant_a",
                {"catalogRole": {"name": "writer_a_catalog"}},
            )
            management(
                "PUT",
                "/catalogs/tenant_a/catalog-roles/writer_a_catalog/grants",
                {"type": "catalog", "privilege": "CATALOG_MANAGE_CONTENT"},
            )
            # Token values live only in this process. The adapter receives the
            # environment-variable name, never a token in argv or a config file.
            token_name = "TRUSTOPS_POLARIS_SMOKE_TOKEN"
            os.environ[token_name] = token(credentials["clientId"], credentials["clientSecret"])
            catalog = rest_catalog(
                base + "/api/catalog", warehouse="tenant_a", token_env=token_name, allow_http_localhost=True
            )
            catalog.create_namespace("evidence_scope", properties={"trustops.tenant_id": "acme-prod"})
            lake = root / "lake"
            raw_rows = read_jsonl(ROOT / "data/raw/security_events.jsonl")
            raw_rows[0]["connector_id"] = "interop-fixture"
            raw = root / "raw.jsonl"
            write_jsonl(raw, raw_rows)
            run_pipeline(raw, lake, tenant_id="acme-prod")
            expected = [
                {"connector_id": None, "source_event_id": None, **row}
                for row in read_jsonl(lake / "silver/normalized_events.jsonl")
            ]
            first = publish_iceberg(lake, catalog, namespace="evidence_scope", tenant_id="acme-prod")
            retry = publish_iceberg(lake, catalog, namespace="evidence_scope", tenant_id="acme-prod")
            assert retry["snapshot_id"] == first["snapshot_id"] and retry["already_published"]
            table = catalog.load_table(("evidence_scope", "evidence"))
            with duckdb.connect() as db:
                db.execute("INSTALL iceberg")
                db.execute("LOAD iceberg")
                cursor = db.execute("SELECT * FROM iceberg_scan(?) ORDER BY event_id", [table.metadata_location])
                fields = [field[0] for field in cursor.description]
                actual = [dict(zip(fields, row, strict=True)) for row in cursor.fetchall()]
                assert actual == sorted(expected, key=lambda row: row["event_id"])
                from pyiceberg.types import StringType

                with table.update_schema() as update:
                    update.add_column("review_note", StringType(), required=False)
                changed = root / "changed.jsonl"
                write_jsonl(changed, read_jsonl(ROOT / "data/raw/security_events.jsonl")[:1])
                run_pipeline(changed, lake, tenant_id="acme-prod")
                second = publish_iceberg(lake, catalog, namespace="evidence_scope", tenant_id="acme-prod")
                table = catalog.load_table(("evidence_scope", "evidence"))
                assert db.execute("SELECT count(*) FROM iceberg_scan(?)", [table.metadata_location]).fetchone() == (1,)
                assert db.execute(
                    "SELECT count(*) FROM iceberg_scan(?, snapshot_from_id=?)",
                    [table.metadata_location, first["snapshot_id"]],
                ).fetchone() == (10,)
                assert db.execute("SELECT review_note FROM iceberg_scan(?)", [table.metadata_location]).fetchone() == (
                    None,
                )
                report["duckdb_version"] = duckdb.__version__
            try:
                denied = rest_catalog(
                    base + "/api/catalog", warehouse="tenant_b", token_env=token_name, allow_http_localhost=True
                )
                denied.list_namespaces()
            except ForbiddenError:
                report["catalog_permission_denial"] = True
            except Exception:  # noqa: BLE001 - any non-REST denial fails the smoke
                # Only a real REST denial is acceptable, not a local scope check.
                raise RuntimeError("unexpected cross-catalog denial type") from None
            else:
                raise RuntimeError("writer unexpectedly accessed the other catalog")
            report.update(
                {
                    "row_parity": True,
                    "retry_same_snapshot": True,
                    "historical_read": True,
                    "optional_schema_evolution": True,
                    "initial_rows": 10,
                    "current_rows": 1,
                    "first_snapshot_id": first["snapshot_id"],
                    "second_snapshot_id": second["snapshot_id"],
                    "passed": True,
                }
            )
            return report
        finally:
            os.umask(previous_umask)
            os.environ.pop("TRUSTOPS_POLARIS_SMOKE_TOKEN", None)
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)
            session.close()


if __name__ == "__main__":
    try:
        print(json.dumps(run(), indent=2, sort_keys=True))
    except Exception as error:  # noqa: BLE001 - redacts provider errors before exit
        # Do not emit arbitrary HTTP/provider errors, request bodies, or tokens.
        causes = []
        cause = error
        while cause is not None and len(causes) < 5:
            causes.append(type(cause).__name__)
            cause = cause.__cause__ or cause.__context__
        print(json.dumps({"passed": False, "error_types": causes}))
        raise SystemExit(1) from None
