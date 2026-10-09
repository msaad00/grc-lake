"""Tests for executive PDF export from assessment snapshots."""

from __future__ import annotations

import json
from http import HTTPStatus
from pathlib import Path

from security_lakehouse.assessment import load_snapshot, resolve_snapshot_path, write_assessment_snapshot
from security_lakehouse.reporting.executive_pdf import render_executive_pdf
from test_api_v1 import _request, _seed_lake, _spin
from test_pipeline import RAW, run_pipeline


def test_render_executive_pdf_produces_valid_pdf(tmp_path: Path) -> None:
    run_pipeline(RAW, tmp_path / "lake")
    snapshot = write_assessment_snapshot(tmp_path / "lake", output=tmp_path / "snapshot.json", reason="audit_request")
    assessment = json.loads(snapshot.read_text(encoding="utf-8"))

    pdf = render_executive_pdf(assessment)

    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 500


def test_resolve_snapshot_path_by_stem_and_hash_prefix(tmp_path: Path) -> None:
    run_pipeline(RAW, tmp_path / "lake")
    snapshot = write_assessment_snapshot(
        tmp_path / "lake",
        output=tmp_path / "lake" / "gold" / "snapshots" / "assessment-test.json",
    )
    assessment = json.loads(snapshot.read_text(encoding="utf-8"))
    digest = assessment["assessment_hash"]

    assert resolve_snapshot_path(tmp_path / "lake", "assessment-test") == snapshot
    assert resolve_snapshot_path(tmp_path / "lake", digest[:12]) == snapshot
    assert load_snapshot(tmp_path / "lake", "assessment-test")["assessment_hash"] == digest


def test_resolve_snapshot_path_rejects_unsafe_ids(tmp_path: Path) -> None:
    run_pipeline(RAW, tmp_path / "lake")
    assert resolve_snapshot_path(tmp_path / "lake", "../etc/passwd") is None
    assert resolve_snapshot_path(tmp_path / "lake", "assessment/../../secret") is None


def test_v1_snapshot_pdf_export_endpoint(tmp_path: Path) -> None:
    lake = tmp_path / "lake"
    run_pipeline(RAW, lake)
    snapshot_path = write_assessment_snapshot(lake, reason="monthly_review")
    snapshot_id = snapshot_path.stem

    server = _spin(lake)
    try:
        status, body, headers = _request_raw(server, "GET", f"/api/v1/snapshots/{snapshot_id}/export.pdf")
        assert status == HTTPStatus.OK
        content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
        assert content_type.startswith("application/pdf")
        assert body.startswith(b"%PDF")

        missing_status, missing_body, _ = _request_raw(server, "GET", "/api/v1/snapshots/does-not-exist/export.pdf")
        assert missing_status == HTTPStatus.NOT_FOUND
        assert missing_body["errors"][0]["code"] == "not_found"
    finally:
        server.shutdown()


def test_v1_catalog_advertises_snapshot_pdf_export(tmp_path: Path) -> None:
    server = _spin(tmp_path)
    try:
        status, body = _request(server, "GET", "/api/v1")
        assert status == HTTPStatus.OK
        by_path = {item["path"]: item for item in body["data"]["resources"]}
        export = by_path["/api/v1/snapshots/{snapshot_id}/export.pdf"]
        assert export["resource"] == "snapshots.export"
        assert export["methods"] == ["GET"]
    finally:
        server.shutdown()


def _hostile_assessment() -> dict:
    return {
        "evaluated_at": "<b>2026",
        "snapshot_reason": "<img src='/etc/passwd' width='1' height='1'/>",
        "assessment_hash": "</font><a href='javascript:app.alert(1)'>x</a>",
        "catalog_bundle": {"bundle_id": "<a href='javascript:app.alert(2)'>bundle</a>"},
        "posture": {},
        "evidence_freshness": {"count": "<b>", "stale_count": "<i>"},
    }


def test_render_executive_pdf_escapes_untrusted_markup(monkeypatch) -> None:
    import reportlab.platypus.paraparser as paraparser

    opened: list[object] = []
    real_start_img = paraparser.ParaParser.start_img

    def spy(self, attributes):
        opened.append(attributes)
        return real_start_img(self, attributes)

    monkeypatch.setattr(paraparser.ParaParser, "start_img", spy)
    pdf = render_executive_pdf(_hostile_assessment(), org_name="<a href='javascript:app.alert(3)'>Org</a>")
    assert pdf.startswith(b"%PDF")
    assert b"javascript:" not in pdf
    assert opened == []


def test_v1_snapshot_pdf_export_survives_markup_in_reason(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from security_lakehouse.server_app import create_app

    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path, require_auth=False), raise_server_exceptions=False)
    for reason in ("<b>q3", "<img src='/etc/passwd' width='1' height='1'/>", "<a href='javascript:app.alert(1)'>r</a>"):
        assert client.post("/api/v1/snapshots", json={"reason": reason}).status_code == 201
        sid = client.get("/api/v1/snapshots").json()["data"][0]["snapshot_id"]
        resp = client.get(f"/api/v1/snapshots/{sid}/export.pdf")
        assert resp.status_code == 200, reason
        assert b"javascript:" not in resp.content


def _request_raw(server, method: str, path: str):
    """Like tests.test_api_v1._request but returns raw bytes for PDF responses."""
    import http.client

    host, port = server.server_address
    conn = http.client.HTTPConnection(host, port, timeout=30)
    conn.request(method, path)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    headers = {k: v for k, v in resp.getheaders()}
    content_type = next((v for k, v in resp.getheaders() if k.lower() == "content-type"), "")
    if content_type.startswith("application/pdf") or raw.startswith(b"%PDF"):
        return resp.status, raw, headers
    return resp.status, json.loads(raw.decode("utf-8")), headers
