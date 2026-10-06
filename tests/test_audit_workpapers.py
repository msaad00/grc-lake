"""Workpaper reproducibility, hostile drafts, review authority, and immutable scope."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from security_lakehouse.auth.sessions import SESSION_COOKIE, encode_session_cookie
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user, create_user_session
from security_lakehouse.pipeline import run_pipeline
from security_lakehouse.server_app import create_app


@pytest.fixture
def workpaper_env(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app)
    headers = {}
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="audit", name="Audit")
        for name, role in [("author", "admin"), ("reviewer", "compliance_reviewer"), ("reader", "read_only")]:
            user = create_user(session, tenant_id=tenant.id, email=f"{name}@example.test", role=role)
            _, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
            headers[name] = {"Authorization": f"Bearer {token}"}
            if name == "reviewer":
                headers["reviewer_key"] = dict(headers[name])
                _, session_token = create_user_session(session, tenant_id=tenant.id, user_id=user.id, idp="oidc")
                headers[name] = {"Cookie": f"{SESSION_COOKIE}={encode_session_cookie(session_token)}"}
        foreign = create_tenant(session, slug="other", name="Other")
        user = create_user(session, tenant_id=foreign.id, email="foreign@example.test", role="admin")
        _, token = create_api_key(session, tenant_id=foreign.id, user_id=user.id)
        headers["foreign"] = {"Authorization": f"Bearer {token}"}
    root = Path(__file__).resolve().parents[1] / "examples/control-assurance"
    lake = tmp_path / "tenants" / tenant.id
    run_pipeline(root / "events.jsonl", lake, tenant_id=tenant.id)
    plan = json.loads((root / "plan.json").read_text())
    plan["tenant_id"] = tenant.id
    baseline = json.loads((root / "baseline.json").read_text())
    baseline["tenant_id"] = tenant.id
    return app, client, headers, lake, {"plan": plan, "baseline": baseline}


def test_review_requires_independent_authority_and_exact_digest(workpaper_env):
    _, client, headers, _, body = workpaper_env
    denied = client.post("/api/v1/audit-workpapers", json=body, headers=headers["reader"])
    assert denied.status_code == 403
    response = client.post("/api/v1/audit-workpapers", json=body, headers=headers["author"])
    assert response.status_code == 201
    row = response.json()["data"]
    assert row["status"] == "draft"
    url = f"/api/v1/audit-workpapers/{row['id']}"
    review = {
        "decision": "approve",
        "rationale": "Reviewed scope, gaps, sample selection and lineage",
        "content_sha256": row["content_sha256"],
    }
    assert client.post(url + "/review", json=review, headers=headers["author"]).status_code == 403
    assert client.post(url + "/review", json=review, headers=headers["reader"]).status_code == 403
    assert client.get(url, headers=headers["foreign"]).status_code == 404
    assert client.post(url + "/review", json=review, headers=headers["foreign"]).status_code == 404
    assert (
        client.post(
            url + "/review", json={**review, "content_sha256": "0" * 64}, headers=headers["reviewer"]
        ).status_code
        == 409
    )
    assert client.post(url + "/review", json=review, headers=headers["reviewer_key"]).status_code == 403
    approved = client.post(url + "/review", json=review, headers=headers["reviewer"])
    assert approved.status_code == 200
    assert approved.json()["data"]["reviewed_by"] == "reviewer@example.test"
    assert approved.json()["data"]["review_scope"] == "workpaper_review_only"
    assert approved.json()["data"]["content_sha256"] == row["content_sha256"]
    assert client.post(url + "/review", json=review, headers=headers["reviewer"]).status_code == 409
    current = client.get(url, headers=headers["reviewer"]).json()["data"]
    assert current["content"]["population"]["status"] == "incomplete"
    assert current["content"]["assurance"]["controls"][1]["operating"]["status"] == "sample_fail"


@pytest.mark.parametrize(
    "patch",
    [
        {"citations": ["invented"], "narrative": "Everything complies"},
        {"narrative": "Unsupported", "citations": []},
        {"reviewed_by": "forged"},
    ],
)
def test_uncited_or_forged_drafts_are_rejected(workpaper_env, patch):
    _, client, headers, _, body = workpaper_env
    response = client.post("/api/v1/audit-workpapers", json={**body, **patch}, headers=headers["author"])
    assert response.status_code in (400, 422)


def test_html_escapes_drafts_and_retains_factual_gaps(workpaper_env):
    _, client, headers, _, body = workpaper_env
    body.update(narrative="<script>alert('unsafe')</script>", citations=["day2-1"])
    row = client.post("/api/v1/audit-workpapers", json=body, headers=headers["author"]).json()["data"]
    response = client.get(f"/api/v1/audit-workpapers/{row['id']}/html", headers=headers["author"])
    assert response.status_code == 200
    assert "<script>" not in response.text
    assert "&lt;script&gt;" in response.text
    assert "Draft" in response.text
    assert "synthetic-asset-5" in response.text
    assert "day2-1" in response.text


def test_workpaper_api_retains_declared_asset_without_evidence(workpaper_env):
    _, client, headers, _, body = workpaper_env
    response = client.post("/api/v1/audit-workpapers", json=body, headers=headers["author"])
    assert response.status_code == 201
    row = response.json()["data"]
    operating = [item["operating"] for item in row["content"]["assurance"]["controls"]]
    assert [item["status"] for item in operating] == [
        "insufficient_evidence",
        "sample_fail",
        "insufficient_evidence",
        "insufficient_evidence",
        "insufficient_evidence",
    ]
    assert all(any(gap["asset_id"] == "synthetic-asset-5" for gap in item["gaps"]) for item in operating)
    html = client.get(f"/api/v1/audit-workpapers/{row['id']}/html", headers=headers["author"])
    assert html.status_code == 200
    assert "<strong>0</strong><span>Passing sample sets</span>" in html.text


def test_local_bundle_is_reproducible_and_never_overwrites(workpaper_env, tmp_path):
    from security_lakehouse.audit_workpapers import build_workpaper, export_workpaper, verify_workpaper_export

    _, _, _, lake, body = workpaper_env
    first = build_workpaper(lake, **body)
    assert build_workpaper(lake, **body) == first
    out = tmp_path / "workpaper-export"
    export_workpaper(first, out)
    assert verify_workpaper_export(out)["ok"] is True
    with pytest.raises(FileExistsError):
        export_workpaper(first, out)
    (out / "index.html").write_text("tampered")
    assert verify_workpaper_export(out)["ok"] is False


def test_foreign_scope_and_tampered_stored_content_fail_closed(workpaper_env):
    from security_lakehouse.db.models import AuditWorkpaper

    app, client, headers, _, body = workpaper_env
    response = client.post(
        "/api/v1/audit-workpapers",
        json={**body, "plan": {**body["plan"], "tenant_id": "foreign"}},
        headers=headers["author"],
    )
    assert response.status_code == 400
    row = client.post("/api/v1/audit-workpapers", json=body, headers=headers["author"]).json()["data"]
    foreign_rows = client.get("/api/v1/audit-workpapers", headers=headers["foreign"]).json()["data"]
    assert foreign_rows == []
    with session_scope(app.state.sessionmaker) as session:
        session.get(AuditWorkpaper, row["id"]).content_json = "{}"
    assert client.get(f"/api/v1/audit-workpapers/{row['id']}", headers=headers["author"]).status_code == 409


def test_linked_remediation_is_snapshotted_with_receipts(workpaper_env):
    from security_lakehouse.db import remediation

    app, client, headers, _, body = workpaper_env
    tenant_id = body["plan"]["tenant_id"]
    with session_scope(app.state.sessionmaker) as session:
        task = remediation.create_task(
            session, tenant_id=tenant_id, control_id="SOC2-CC6.1", title="Synthetic follow-up"
        )
        task.verification_history = json.dumps(
            [
                {
                    "verified_at": "2026-01-02T00:00:00Z",
                    "generation": {"generation_id": "synthetic-prior-retest"},
                    "evidence": [{"event_id": "synthetic-prior-event"}],
                }
            ]
        )
        task_id = task.id
    row = client.post("/api/v1/audit-workpapers", json=body, headers=headers["author"]).json()["data"]
    tasks = row["content"]["remediation"]["tasks"]
    assert tasks[0]["id"] == task_id
    assert tasks[0]["verification_history"][0]["generation"]["generation_id"] == "synthetic-prior-retest"
    with session_scope(app.state.sessionmaker) as session:
        remediation.update_task(session, tenant_id=tenant_id, task_id=task_id, changes={"title": "Later change"})
    frozen = client.get(f"/api/v1/audit-workpapers/{row['id']}", headers=headers["author"]).json()["data"]
    assert frozen["content"]["remediation"]["tasks"][0]["title"] == "Synthetic follow-up"


def test_workpaper_cli_exports_and_verifies(workpaper_env, tmp_path, capsys):
    from security_lakehouse.cli import main

    _, _, _, lake, body = workpaper_env
    paths = {}
    for name in ("plan", "baseline"):
        paths[name] = tmp_path / f"{name}.json"
        paths[name].write_text(json.dumps(body[name]))
    out = tmp_path / "cli-workpaper"
    exit_code = main(
        [
            "assessment",
            "workpaper",
            "--lake",
            str(lake),
            "--plan",
            str(paths["plan"]),
            "--baseline",
            str(paths["baseline"]),
            "--out",
            str(out),
        ]
    )
    assert exit_code == 0
    capsys.readouterr()
    exit_code = main(["assessment", "verify-workpaper", "--dir", str(out)])
    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True


@pytest.mark.parametrize("tamper", ["html_and_manifest", "extra_file", "symlink"])
def test_export_rejects_inconsistent_html_and_unexpected_files(workpaper_env, tmp_path, tamper):
    from security_lakehouse.audit_workpapers import build_workpaper, export_workpaper, verify_workpaper_export
    from security_lakehouse.io import file_sha256

    _, _, _, lake, body = workpaper_env
    out = tmp_path / "bundle"
    export_workpaper(build_workpaper(lake, **body), out)
    html = out / "index.html"
    if tamper == "html_and_manifest":
        html.write_text("<h1>All controls passed</h1>")
        manifest = json.loads((out / "manifest.json").read_text())
        manifest["files"]["index.html"] = file_sha256(html)
        (out / "manifest.json").write_text(json.dumps(manifest))
    elif tamper == "extra_file":
        (out / "unexpected.js").write_text("unreviewed content")
    else:
        target = tmp_path / "elsewhere.html"
        html.rename(target)
        html.symlink_to(target)
    assert verify_workpaper_export(out)["ok"] is False


def test_mixed_inputs_retain_synthetic_provenance(workpaper_env, tmp_path):
    from security_lakehouse.audit_workpapers import build_workpaper, render_workpaper
    from security_lakehouse.io import read_jsonl, write_jsonl

    _, _, _, lake, body = workpaper_env
    source = Path(__file__).resolve().parents[1] / "examples/control-assurance/events.jsonl"
    rows = read_jsonl(source)
    rows[-1]["source"] = "provider-evidence"
    raw = tmp_path / "mixed.jsonl"
    write_jsonl(raw, rows)
    run_pipeline(raw, lake, tenant_id=body["plan"]["tenant_id"])
    content = build_workpaper(lake, **body)
    assert content["synthetic_fixture"] is True
    assert "Synthetic" in render_workpaper(content)


def test_legacy_export_migration_requires_matching_original_json(workpaper_env, tmp_path):
    from security_lakehouse.audit_workpapers import build_workpaper, export_workpaper, verify_workpaper_export
    from security_lakehouse.evidence_migration import migrate_workpaper
    from security_lakehouse.io import file_sha256

    _, _, _, lake, body = workpaper_env
    old = tmp_path / "old-export"
    content = build_workpaper(lake, **body)
    export_workpaper(content, old)
    original_json = tmp_path / "original-workpaper.json"
    (old / "workpaper.json").rename(original_json)
    manifest = json.loads((old / "manifest.json").read_text())
    manifest["files"].pop("workpaper.json")
    manifest.pop("render_version")
    (old / "manifest.json").write_text(json.dumps(manifest))
    before = file_sha256(old / "manifest.json")
    with pytest.raises(ValueError, match="JSON is required"):
        migrate_workpaper(old, tmp_path / "missing")
    migrate_workpaper(old, tmp_path / "new-export", content_path=original_json)
    assert verify_workpaper_export(tmp_path / "new-export")["ok"]
    assert file_sha256(old / "manifest.json") == before
    original_json.write_text("{}")
    with pytest.raises(ValueError, match="recorded content hash"):
        migrate_workpaper(old, tmp_path / "forged", content_path=original_json)
