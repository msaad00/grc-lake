"""Outbound event webhooks: subscriptions, signing, delivery/retry, RBAC, and the
assessment-engine hook that detects new findings and newly-failing controls.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from fastapi.testclient import TestClient
from sqlalchemy import inspect

from security_lakehouse import netguard, webhook_delivery
from security_lakehouse.assessment import verify_snapshot_chain, write_assessment_snapshot
from security_lakehouse.db import migrate
from security_lakehouse.db import webhooks as webhooks_db
from security_lakehouse.db.base import create_engine_for, session_scope
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.scheduler import tick
from security_lakehouse.server_app import create_app
from security_lakehouse.services import webhooks as webhook_services
from security_lakehouse.workflows import save_workflow
from test_api_v1 import _seed_lake


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _provision(app, slug: str, role: str = "security_admin") -> tuple[str, str]:
    """Create a tenant + user + API key; return (tenant_id, token)."""
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug=slug, name=slug.title())
        user = create_user(session, tenant_id=tenant.id, email=f"{role}@{slug}.test", role=role)
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        return tenant.id, token


@pytest.fixture
def env(tmp_path: Path):
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    tokens: dict[str, str] = {}
    tenant_id = ""
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        tenant_id = tenant.id
        for role in ("read_only", "contributor", "security_admin"):
            user = create_user(session, tenant_id=tenant.id, email=f"{role}@acme.test", role=role)
            _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
            tokens[role] = token
    return app, client, tokens, tenant_id


@pytest.fixture(autouse=True)
def _public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default: every host resolves to a public IP unless a test overrides it."""

    def _getaddrinfo(host, port, *args, **kwargs):
        return [(2, 1, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(netguard.socket, "getaddrinfo", _getaddrinfo)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never actually sleep during retry backoff -- keeps the suite fast."""
    monkeypatch.setattr(webhook_delivery, "_backoff_sleep", lambda _s: None)


class _FakeResponse:
    """Minimal stand-in for the urlopen context-manager response."""

    def __init__(self, status: int, body: bytes = b"ok") -> None:
        self.status = status
        self._body = body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self, amt: int | None = None) -> bytes:
        return self._body


def _append_event(lake: Path, event: dict[str, object]) -> None:
    path = lake / "silver" / "normalized_events.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows.append(event)
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8")


_NEW_VIOLATION_EVENT_TEMPLATE = {
    "event_time": "2026-05-21T00:00:00Z",
    "event_type": "identity.access_review",
    "asset_owner": "security-platform",
    "asset_type": "iam_role",
    "environment": "prod",
    "source": "okta",
    "status": "open",
    "severity": "critical",
    "severity_score": 95,
    "raw_sha256": "xyz",
}


# --- migration ---------------------------------------------------------------


def test_migration_creates_webhook_tables(tmp_path: Path) -> None:
    migrate.upgrade(tmp_path)
    engine = create_engine_for(tmp_path)
    inspector = inspect(engine)
    assert "webhook_subscriptions" in inspector.get_table_names()
    assert "webhook_deliveries" in inspector.get_table_names()
    columns = {col["name"] for col in inspector.get_columns("webhook_subscriptions")}
    assert {"id", "tenant_id", "url", "secret", "event_types_json", "enabled"} <= columns
    index_names = {ix["name"] for ix in inspector.get_indexes("webhook_subscriptions")}
    assert "ix_webhook_subscriptions_tenant_enabled" in index_names


# --- db repository -------------------------------------------------------------


def test_subscription_crud_round_trip(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        sub = webhooks_db.create_subscription(
            session,
            tenant_id=tenant.id,
            url="https://hooks.example.com/x",
            secret="s3cr3t-value-1234",
            event_types=["assessment.completed"],
        )
        assert sub.enabled is True
        assert webhooks_db.get_subscription(session, tenant_id=tenant.id, subscription_id=sub.id) is not None
        assert len(webhooks_db.list_subscriptions(session, tenant_id=tenant.id)) == 1

        updated = webhooks_db.update_subscription(
            session, tenant_id=tenant.id, subscription_id=sub.id, changes={"enabled": False}
        )
        assert updated is not None
        assert updated.enabled is False

        assert webhooks_db.delete_subscription(session, tenant_id=tenant.id, subscription_id=sub.id) is True
        assert webhooks_db.get_subscription(session, tenant_id=tenant.id, subscription_id=sub.id) is None


def test_invalid_event_type_rejected(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        with pytest.raises(ValueError, match="unknown event type"):
            webhooks_db.create_subscription(
                session,
                tenant_id=tenant.id,
                url="https://hooks.example.com/x",
                secret="s3cr3t-value-1234",
                event_types=["not.a.real.event"],
            )


def test_secret_is_never_returned_by_default_serialization(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        sub = webhooks_db.create_subscription(
            session,
            tenant_id=tenant.id,
            url="https://hooks.example.com/x",
            secret="s3cr3t-value-1234",
            event_types=["assessment.completed"],
        )
        assert "secret" not in webhooks_db.subscription_to_dict(sub)
        assert webhooks_db.subscription_to_dict(sub, include_secret=True)["secret"] == "s3cr3t-value-1234"


# --- signing ---------------------------------------------------------------------


def test_sign_and_verify_signature_round_trip() -> None:
    """A receiver recomputes the signature over the raw body and compares."""
    body = json.dumps({"a": 1}, sort_keys=True).encode("utf-8")
    signature = webhook_delivery.sign_payload("my-secret", body)
    assert signature.startswith("sha256=")
    assert webhook_delivery.verify_signature("my-secret", body, signature) is True
    assert webhook_delivery.verify_signature("wrong-secret", body, signature) is False
    assert webhook_delivery.verify_signature("my-secret", body + b"tampered", signature) is False


# --- delivery + retry --------------------------------------------------------------


def test_deliver_webhook_success_signs_and_posts(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[urllib.request.Request] = []

    def _fake_open_guarded(request, *, timeout=None, validate=None):
        captured.append(request)
        return _FakeResponse(200)

    monkeypatch.setattr(webhook_delivery.netguard, "open_guarded", _fake_open_guarded)
    envelope = webhook_delivery.build_envelope(
        event_type="assessment.completed", tenant_id="tenant-1", occurred_at="2026-01-01T00:00:00+00:00", data={"x": 1}
    )
    result = webhook_delivery.deliver_webhook(
        "https://hooks.example.com/x", secret="s3cr3t", event_type="assessment.completed", envelope=envelope
    )
    assert result == {"ok": True, "status_code": 200, "attempts": 1, "error": None}
    assert len(captured) == 1
    sent = captured[0]
    signature = sent.get_header("X-trustops-signature")
    assert signature is not None
    assert webhook_delivery.verify_signature("s3cr3t", sent.data, signature)
    assert sent.get_header("X-trustops-event") == "assessment.completed"


def test_deliver_webhook_non_2xx_is_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        webhook_delivery.netguard, "open_guarded", lambda request, *, timeout=None, validate=None: _FakeResponse(500)
    )
    envelope = webhook_delivery.build_envelope(event_type="x", tenant_id="t", occurred_at="now", data={})
    result = webhook_delivery.deliver_webhook(
        "https://hooks.example.com/x", secret="s", event_type="x", envelope=envelope, max_retries=0
    )
    assert result["ok"] is False
    assert result["attempts"] == 1
    assert result["status_code"] == 500


def test_deliver_webhook_retries_and_succeeds_on_second_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def _flaky(request, *, timeout=None, validate=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise urllib.error.URLError("boom")
        return _FakeResponse(200)

    monkeypatch.setattr(webhook_delivery.netguard, "open_guarded", _flaky)
    envelope = webhook_delivery.build_envelope(event_type="x", tenant_id="t", occurred_at="now", data={})
    result = webhook_delivery.deliver_webhook(
        "https://hooks.example.com/x", secret="s", event_type="x", envelope=envelope, max_retries=1
    )
    assert result == {"ok": True, "status_code": 200, "attempts": 2, "error": None}
    assert calls["n"] == 2


def test_deliver_webhook_exhausts_retries_and_reports_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        webhook_delivery.netguard,
        "open_guarded",
        lambda request, *, timeout=None, validate=None: (_ for _ in ()).throw(TimeoutError("slow receiver")),
    )
    envelope = webhook_delivery.build_envelope(event_type="x", tenant_id="t", occurred_at="now", data={})
    result = webhook_delivery.deliver_webhook(
        "https://hooks.example.com/x", secret="s", event_type="x", envelope=envelope, max_retries=1
    )
    assert result["ok"] is False
    assert result["attempts"] == 2
    assert "TimeoutError" in (result["error"] or "")


def test_deliver_webhook_ssrf_blocked_url_fails_without_an_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(netguard.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 0))])
    envelope = webhook_delivery.build_envelope(event_type="x", tenant_id="t", occurred_at="now", data={})
    result = webhook_delivery.deliver_webhook(
        "http://internal.example.com/x", secret="s", event_type="x", envelope=envelope
    )
    assert result["ok"] is False
    assert result["attempts"] == 0
    assert "SSRF" in (result["error"] or "")


# --- optional destination allowlist (review finding #9) ----------------------


def test_deliver_webhook_allows_any_public_url_when_allowlist_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default behavior (no TRUSTOPS_WEBHOOK_EGRESS_ALLOWLIST set) is unchanged:
    any public URL is deliverable -- the self-service webhook model."""
    monkeypatch.delenv(webhook_delivery.EGRESS_ALLOWLIST_ENV, raising=False)
    monkeypatch.setattr(
        webhook_delivery.netguard, "open_guarded", lambda request, *, timeout=None, validate=None: _FakeResponse(200)
    )
    envelope = webhook_delivery.build_envelope(event_type="x", tenant_id="t", occurred_at="now", data={})
    result = webhook_delivery.deliver_webhook(
        "https://anywhere-public.example.com/x", secret="s", event_type="x", envelope=envelope
    )
    assert result["ok"] is True


def test_deliver_webhook_rejects_non_allowlisted_host_when_allowlist_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(webhook_delivery.EGRESS_ALLOWLIST_ENV, "siem.example.com")
    envelope = webhook_delivery.build_envelope(event_type="x", tenant_id="t", occurred_at="now", data={})
    result = webhook_delivery.deliver_webhook(
        "https://not-siem.example.com/x", secret="s", event_type="x", envelope=envelope
    )
    assert result["ok"] is False
    assert result["attempts"] == 0
    assert "TRUSTOPS_WEBHOOK_EGRESS_ALLOWLIST" in (result["error"] or "")


def test_deliver_webhook_allows_allowlisted_host_when_allowlist_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(webhook_delivery.EGRESS_ALLOWLIST_ENV, "siem.example.com")
    monkeypatch.setattr(
        webhook_delivery.netguard, "open_guarded", lambda request, *, timeout=None, validate=None: _FakeResponse(200)
    )
    envelope = webhook_delivery.build_envelope(event_type="x", tenant_id="t", occurred_at="now", data={})
    result = webhook_delivery.deliver_webhook(
        "https://siem.example.com/ingest", secret="s", event_type="x", envelope=envelope
    )
    assert result["ok"] is True


# --- dispatch orchestration ---------------------------------------------------


def test_dispatch_event_fans_out_to_matching_enabled_subscriptions_only(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        match = webhooks_db.create_subscription(
            session,
            tenant_id=tenant.id,
            url="https://hooks.example.com/match",
            secret="s3cr3t-value-1234",
            event_types=["assessment.completed"],
        )
        webhooks_db.create_subscription(
            session,
            tenant_id=tenant.id,
            url="https://hooks.example.com/wrong-type",
            secret="s3cr3t-value-1234",
            event_types=["finding.created"],
        )
        webhooks_db.create_subscription(
            session,
            tenant_id=tenant.id,
            url="https://hooks.example.com/disabled",
            secret="s3cr3t-value-1234",
            event_types=["assessment.completed"],
            enabled=False,
        )
        session.commit()

        calls: list[str] = []

        def _deliver(url, *, secret, event_type, envelope):
            calls.append(url)
            return {"ok": True, "status_code": 200, "attempts": 1, "error": None}

        results = webhook_services.dispatch_event(
            session, tenant.id, event_type="assessment.completed", data={"x": 1}, deliver=_deliver
        )
        assert calls == ["https://hooks.example.com/match"]
        assert len(results) == 1

        deliveries = webhook_services.list_deliveries(session, tenant.id, subscription_id=match.id)
        assert len(deliveries) == 1
        assert deliveries[0]["status"] == "success"


def test_dispatch_event_delivery_failure_is_recorded_not_raised(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        webhooks_db.create_subscription(
            session,
            tenant_id=tenant.id,
            url="https://hooks.example.com/dead",
            secret="s3cr3t-value-1234",
            event_types=["assessment.completed"],
        )
        session.commit()

        def _deliver(url, *, secret, event_type, envelope):
            raise RuntimeError("network exploded")

        results = webhook_services.dispatch_event(
            session, tenant.id, event_type="assessment.completed", data={}, deliver=_deliver
        )
        assert results[0]["ok"] is False

        deliveries = webhook_services.list_deliveries(session, tenant.id)
        assert len(deliveries) == 1
        assert deliveries[0]["status"] == "failed"


# --- assessment-engine hook: violation diff + control transitions ------------------


def test_snapshot_hook_fires_only_assessment_completed_on_first_snapshot(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    calls: list[tuple] = []
    write_assessment_snapshot(tmp_path, reason="first", on_snapshot_written=lambda *a: calls.append(a))
    assert len(calls) == 1
    _path, _assessment, new_violations, newly_failing_controls = calls[0]
    # No prior snapshot to diff against -- nothing is reported as "new".
    assert new_violations == []
    assert newly_failing_controls == []


def test_snapshot_hook_detects_new_violation_and_newly_failing_control(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    write_assessment_snapshot(tmp_path, reason="baseline")  # establishes the prior snapshot, no hook

    _append_event(
        tmp_path,
        {
            **_NEW_VIOLATION_EVENT_TEMPLATE,
            "event_id": "evt-999",
            "control_ids": ["SOC2-CC7.1"],
            "asset_id": "aws:iam:role/new",
            "evidence_ref": "s3://evidence/evt-999.json",
        },
    )

    calls: list[tuple] = []
    write_assessment_snapshot(tmp_path, reason="second", on_snapshot_written=lambda *a: calls.append(a))
    assert len(calls) == 1
    _path, _assessment, new_violations, newly_failing_controls = calls[0]
    assert [v["violation_id"] for v in new_violations] == ["SOC2-CC7.1:evt-999"]
    assert newly_failing_controls == ["SOC2-CC7.1"]


def test_snapshot_hook_does_not_refire_control_failed_for_an_already_failing_control(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    write_assessment_snapshot(tmp_path, reason="baseline")  # SOC2-CC6.1 already has an open violation (evt-001)

    _append_event(
        tmp_path,
        {
            **_NEW_VIOLATION_EVENT_TEMPLATE,
            "event_id": "evt-998",
            "control_ids": ["SOC2-CC6.1"],
            "asset_id": "aws:iam:role/admin2",
            "evidence_ref": "s3://evidence/evt-998.json",
        },
    )

    calls: list[tuple] = []
    write_assessment_snapshot(tmp_path, reason="second", on_snapshot_written=lambda *a: calls.append(a))
    _path, _assessment, new_violations, newly_failing_controls = calls[0]
    assert [v["violation_id"] for v in new_violations] == ["SOC2-CC6.1:evt-998"]
    # SOC2-CC6.1 was already failing in the prior snapshot -- not a transition.
    assert newly_failing_controls == []


def test_snapshot_hook_failure_does_not_break_the_write(tmp_path: Path) -> None:
    _seed_lake(tmp_path)

    def _boom(*_args: object) -> None:
        raise RuntimeError("webhook receiver exploded")

    path = write_assessment_snapshot(tmp_path, reason="first", on_snapshot_written=_boom)
    assert path.exists()
    result = verify_snapshot_chain(tmp_path)
    assert result["ok"] is True


def test_snapshot_write_rejects_a_tampered_prior_snapshot(tmp_path: Path) -> None:
    """Tampered history must fail explicitly before any new snapshot or webhook."""
    _seed_lake(tmp_path)
    first = write_assessment_snapshot(tmp_path, reason="baseline")
    payload = json.loads(first.read_text(encoding="utf-8"))
    assert payload["violations"], "fixture must produce at least one violation to corrupt"
    payload["violations"][0]["violation_id"] = ["not", "a", "string"]  # malformed on purpose
    first.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    calls: list[tuple] = []
    ledger = tmp_path / "gold/snapshots/_ledger.jsonl"
    before = ledger.read_bytes()
    with pytest.raises(ValueError, match="snapshot integrity"):
        write_assessment_snapshot(tmp_path, reason="second", on_snapshot_written=lambda *a: calls.append(a))
    assert ledger.read_bytes() == before
    assert calls == []


def test_write_assessment_snapshot_succeeds_even_when_every_webhook_delivery_fails(tmp_path: Path) -> None:
    """The real dispatch_snapshot_events hook, wired with an always-failing transport."""
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        webhooks_db.create_subscription(
            session,
            tenant_id=tenant.id,
            url="https://hooks.example.com/dead",
            secret="s3cr3t-value-1234",
            event_types=["assessment.completed"],
        )
        session.commit()

        def _always_fails(url, *, secret, event_type, envelope):
            raise TimeoutError("receiver did not respond")

        def _hook(snapshot_path, assessment, new_violations, newly_failing_controls) -> None:
            webhook_services.dispatch_snapshot_events(
                session,
                tenant.id,
                snapshot_path=snapshot_path,
                assessment=assessment,
                new_violations=new_violations,
                newly_failing_controls=newly_failing_controls,
                deliver=_always_fails,
            )

        path = write_assessment_snapshot(tmp_path, reason="test", on_snapshot_written=_hook)
        assert path.exists()

        deliveries = webhook_services.list_deliveries(session, tenant.id)
        assert len(deliveries) == 1
        assert deliveries[0]["status"] == "failed"
        assert deliveries[0]["event_type"] == "assessment.completed"


# --- API ---------------------------------------------------------------------


def test_webhooks_require_auth(env) -> None:
    _app, client, _tokens, _tenant_id = env
    assert client.get("/api/v1/webhooks").status_code == HTTPStatus.UNAUTHORIZED


def test_webhook_api_crud_and_rbac(env) -> None:
    _app, client, tokens, _tenant_id = env
    # read_only can list, but creating/mutating a webhook needs connector_manage.
    assert client.get("/api/v1/webhooks", headers=_bearer(tokens["read_only"])).status_code == HTTPStatus.OK
    denied = client.post(
        "/api/v1/webhooks",
        json={"url": "https://hooks.example.com/x", "event_types": ["assessment.completed"]},
        headers=_bearer(tokens["read_only"]),
    )
    assert denied.status_code == HTTPStatus.FORBIDDEN
    # contributor (write, but not connector_manage) is denied too.
    denied_contributor = client.post(
        "/api/v1/webhooks",
        json={"url": "https://hooks.example.com/x", "event_types": ["assessment.completed"]},
        headers=_bearer(tokens["contributor"]),
    )
    assert denied_contributor.status_code == HTTPStatus.FORBIDDEN

    created = client.post(
        "/api/v1/webhooks",
        json={
            "url": "https://hooks.example.com/sink",
            "event_types": ["assessment.completed", "finding.created"],
            "description": "SIEM ingest",
        },
        headers=_bearer(tokens["security_admin"]),
    )
    assert created.status_code == HTTPStatus.CREATED
    body = created.json()["data"]
    assert body["url"] == "https://hooks.example.com/sink"
    assert body["enabled"] is True
    # The secret is handed back in full exactly once, at creation.
    assert isinstance(body.get("secret"), str) and len(body["secret"]) >= 16
    subscription_id = body["id"]

    fetched = client.get(f"/api/v1/webhooks/{subscription_id}", headers=_bearer(tokens["read_only"]))
    assert fetched.status_code == HTTPStatus.OK
    assert "secret" not in fetched.json()["data"]

    patched = client.patch(
        f"/api/v1/webhooks/{subscription_id}",
        json={"enabled": False},
        headers=_bearer(tokens["security_admin"]),
    )
    assert patched.status_code == HTTPStatus.OK
    assert patched.json()["data"]["enabled"] is False

    deleted = client.delete(f"/api/v1/webhooks/{subscription_id}", headers=_bearer(tokens["security_admin"]))
    assert deleted.status_code == HTTPStatus.OK
    assert client.get("/api/v1/webhooks", headers=_bearer(tokens["security_admin"])).json()["data"] == []


def test_webhook_invalid_event_type_is_400(env) -> None:
    _app, client, tokens, _tenant_id = env
    resp = client.post(
        "/api/v1/webhooks",
        json={"url": "https://hooks.example.com/x", "event_types": ["not.a.real.event"]},
        headers=_bearer(tokens["security_admin"]),
    )
    assert resp.status_code == HTTPStatus.BAD_REQUEST


def test_webhook_unknown_field_rejected(env) -> None:
    _app, client, tokens, _tenant_id = env
    resp = client.post(
        "/api/v1/webhooks",
        json={"url": "https://hooks.example.com/x", "event_types": ["assessment.completed"], "bogus": "field"},
        headers=_bearer(tokens["security_admin"]),
    )
    assert resp.status_code == 422


def test_webhook_tenant_isolation(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    _a_id, token_a = _provision(app, "acme")
    _b_id, token_b = _provision(app, "globex")

    created = client.post(
        "/api/v1/webhooks",
        json={"url": "https://hooks.example.com/a-only", "event_types": ["assessment.completed"]},
        headers=_bearer(token_a),
    )
    assert created.status_code == HTTPStatus.CREATED
    subscription_id = created.json()["data"]["id"]

    b_list = client.get("/api/v1/webhooks", headers=_bearer(token_b)).json()["data"]
    assert b_list == []
    b_get = client.get(f"/api/v1/webhooks/{subscription_id}", headers=_bearer(token_b))
    assert b_get.status_code == HTTPStatus.NOT_FOUND
    b_patch = client.patch(f"/api/v1/webhooks/{subscription_id}", json={"enabled": False}, headers=_bearer(token_b))
    assert b_patch.status_code == HTTPStatus.NOT_FOUND
    b_delete = client.delete(f"/api/v1/webhooks/{subscription_id}", headers=_bearer(token_b))
    assert b_delete.status_code == HTTPStatus.NOT_FOUND

    a_list = client.get("/api/v1/webhooks", headers=_bearer(token_a)).json()["data"]
    assert [w["url"] for w in a_list] == ["https://hooks.example.com/a-only"]


def test_snapshot_creation_via_api_dispatches_assessment_completed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """POST /api/v1/snapshots (the documented route) triggers a signed delivery
    after the snapshot write completes, and the outcome is auditable via the
    deliveries endpoint -- exercising the full hook wiring, not just the
    service function in isolation.
    """
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    tenant_id, admin_token = _provision(app, "acme", role="security_admin")

    calls: list[dict] = []

    def _fake_deliver(url, *, secret, event_type, envelope):
        calls.append({"url": url, "secret": secret, "event_type": event_type, "envelope": envelope})
        return {"ok": True, "status_code": 200, "attempts": 1, "error": None}

    monkeypatch.setattr(webhook_services, "deliver_webhook", _fake_deliver)

    created = client.post(
        "/api/v1/webhooks",
        json={"url": "https://hooks.example.com/sink", "event_types": ["assessment.completed"]},
        headers=_bearer(admin_token),
    )
    assert created.status_code == HTTPStatus.CREATED
    subscription_id = created.json()["data"]["id"]
    secret = created.json()["data"]["secret"]

    snap = client.post("/api/v1/snapshots", json={"reason": "api_test"}, headers=_bearer(admin_token))
    assert snap.status_code == HTTPStatus.CREATED

    assert len(calls) == 1
    delivered = calls[0]
    assert delivered["event_type"] == "assessment.completed"
    assert delivered["url"] == "https://hooks.example.com/sink"
    assert delivered["secret"] == secret
    envelope = delivered["envelope"]
    assert envelope["event"] == "assessment.completed"
    assert envelope["tenant_id"] == tenant_id
    assert envelope["data"]["snapshot_reason"] == "api_test"

    deliveries = client.get(f"/api/v1/webhooks/{subscription_id}/deliveries", headers=_bearer(admin_token))
    assert deliveries.status_code == HTTPStatus.OK
    delivery_rows = deliveries.json()["data"]
    assert len(delivery_rows) == 1
    assert delivery_rows[0]["status"] == "success"
    assert delivery_rows[0]["event_type"] == "assessment.completed"


def test_snapshot_creation_via_api_does_not_fail_when_webhook_delivery_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The snapshot API call must succeed even though its subscriber is dead --
    delivery failure is recorded, never raised back through the write path."""
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    _tenant_id, admin_token = _provision(app, "acme", role="security_admin")

    def _dead_receiver(url, *, secret, event_type, envelope):
        raise TimeoutError("receiver did not respond")

    monkeypatch.setattr(webhook_services, "deliver_webhook", _dead_receiver)

    created = client.post(
        "/api/v1/webhooks",
        json={"url": "https://hooks.example.com/dead", "event_types": ["assessment.completed"]},
        headers=_bearer(admin_token),
    )
    assert created.status_code == HTTPStatus.CREATED
    subscription_id = created.json()["data"]["id"]

    snap = client.post("/api/v1/snapshots", json={"reason": "api_test"}, headers=_bearer(admin_token))
    assert snap.status_code == HTTPStatus.CREATED
    assert "snapshot_path" in snap.json()["data"]

    deliveries = client.get(f"/api/v1/webhooks/{subscription_id}/deliveries", headers=_bearer(admin_token))
    assert deliveries.json()["data"][0]["status"] == "failed"


# --- scheduler/workflow-triggered snapshots also dispatch webhooks (review finding #4) ---


def _save_cron_snapshot_workflow(lake: Path, *, schedule: str = "every 1m") -> str:
    workflow = save_workflow(
        lake,
        workflow_id="cron-snapshot",
        name="cron-snapshot",
        description="",
        nodes=[
            {"id": "n1", "node_type": "trigger.cron", "params": {"schedule": schedule}},
            {"id": "n2", "node_type": "action.snapshot", "params": {"reason": "scheduled"}},
        ],
        edges=[{"source": "n1", "target": "n2"}],
    )
    return workflow["workflow_id"]


def test_scheduler_tick_threads_on_snapshot_written_through_run_workflow(tmp_path: Path) -> None:
    """scheduler.tick's REAL run_workflow (no test-injected runner) must reach
    action.snapshot's write_assessment_snapshot call with on_snapshot_written --
    a cron-scheduled snapshot is at least as common a trigger as an interactive
    one, and previously silently skipped webhook dispatch entirely.
    """
    _seed_lake(tmp_path)
    _save_cron_snapshot_workflow(tmp_path)

    calls: list[tuple] = []
    result = tick(tmp_path, on_snapshot_written=lambda *a: calls.append(a))

    assert len(result) == 1
    assert result[0]["result"] == "ok"
    assert len(calls) == 1
    _path, _assessment, _unused_new_violations, _newly_failing = calls[0]


def test_scheduler_tick_with_test_runner_override_does_not_receive_the_hook(tmp_path: Path) -> None:
    """A test-supplied runner= keeps its existing narrow signature -- tick must
    not pass on_snapshot_written to it (that would break every existing
    scheduler test that stubs runner with (lake, *, workflow_id, actor))."""
    _seed_lake(tmp_path)
    workflow_id = _save_cron_snapshot_workflow(tmp_path)
    calls: list[str] = []

    def runner(_lake, *, workflow_id: str, actor: str) -> dict:
        calls.append(workflow_id)
        return {"workflow_id": workflow_id, "actor": actor, "result": "ok"}

    result = tick(tmp_path, runner=runner, on_snapshot_written=lambda *a: None)

    assert calls == [workflow_id]
    assert result[0]["result"] == "ok"


def test_scheduler_tick_via_api_dispatches_assessment_completed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """POST /api/v1/scheduler/tick end-to-end: firing a due cron workflow whose
    DAG contains action.snapshot dispatches a signed webhook delivery, exactly
    like an interactively-triggered POST /api/v1/snapshots does.
    """
    _seed_lake(tmp_path)
    _save_cron_snapshot_workflow(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    _tenant_id, admin_token = _provision(app, "acme", role="security_admin")

    calls: list[dict] = []

    def _fake_deliver(url, *, secret, event_type, envelope):
        calls.append({"event_type": event_type, "envelope": envelope})
        return {"ok": True, "status_code": 200, "attempts": 1, "error": None}

    monkeypatch.setattr(webhook_services, "deliver_webhook", _fake_deliver)

    created = client.post(
        "/api/v1/webhooks",
        json={"url": "https://hooks.example.com/scheduler-sink", "event_types": ["assessment.completed"]},
        headers=_bearer(admin_token),
    )
    assert created.status_code == HTTPStatus.CREATED

    tick_response = client.post("/api/v1/scheduler/tick", headers=_bearer(admin_token))
    assert tick_response.status_code == HTTPStatus.CREATED
    fired = tick_response.json()["data"]["fired"]
    assert len(fired) == 1
    assert fired[0]["result"] == "ok"

    assert len(calls) == 1
    assert calls[0]["event_type"] == "assessment.completed"


# --- pagination must apply after the event_type filter, not before (review finding #7) ---


def test_list_subscriptions_event_type_filter_applies_before_pagination(tmp_path: Path) -> None:
    """A matching subscription that is not among the N most-recently-created
    rows must still be found -- filtering the SQL-paginated page (rather than
    paginating the filtered set) silently drops or undercounts real matches.
    """
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        # Oldest, and the ONLY control.failed subscriber.
        only_match = webhooks_db.create_subscription(
            session,
            tenant_id=tenant.id,
            url="https://hooks.example.com/only-match",
            secret="s3cr3t-value-1234",
            event_types=["control.failed"],
        )
        # Four more recent, non-matching subscriptions -- these fill up any
        # SQL-level LIMIT before a Python-side filter would ever run.
        for i in range(4):
            webhooks_db.create_subscription(
                session,
                tenant_id=tenant.id,
                url=f"https://hooks.example.com/noise-{i}",
                secret="s3cr3t-value-1234",
                event_types=["assessment.completed"],
            )

        # Newest-first order puts every non-matching row ahead of the match;
        # a limit=2 SQL page would contain zero control.failed subscribers.
        results = webhooks_db.list_subscriptions(session, tenant_id=tenant.id, event_type="control.failed", limit=2)
        assert [row.id for row in results] == [only_match.id]


# --- explicit null vs omitted field on PATCH (review finding #8) -------------------


def test_update_subscription_explicit_null_description_clears_it(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        sub = webhooks_db.create_subscription(
            session,
            tenant_id=tenant.id,
            url="https://hooks.example.com/x",
            secret="s3cr3t-value-1234",
            event_types=["assessment.completed"],
            description="will be cleared",
        )
        updated = webhooks_db.update_subscription(
            session, tenant_id=tenant.id, subscription_id=sub.id, changes={"description": None}
        )
        assert updated is not None
        assert updated.description == ""


def test_update_subscription_omitted_description_leaves_it_unchanged(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        sub = webhooks_db.create_subscription(
            session,
            tenant_id=tenant.id,
            url="https://hooks.example.com/x",
            secret="s3cr3t-value-1234",
            event_types=["assessment.completed"],
            description="keep me",
        )
        updated = webhooks_db.update_subscription(
            session, tenant_id=tenant.id, subscription_id=sub.id, changes={"enabled": False}
        )
        assert updated is not None
        assert updated.description == "keep me"


def test_update_subscription_explicit_null_event_types_or_enabled_is_rejected(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        sub = webhooks_db.create_subscription(
            session,
            tenant_id=tenant.id,
            url="https://hooks.example.com/x",
            secret="s3cr3t-value-1234",
            event_types=["assessment.completed"],
        )
        with pytest.raises(ValueError, match="event_types"):
            webhooks_db.update_subscription(
                session, tenant_id=tenant.id, subscription_id=sub.id, changes={"event_types": None}
            )
        with pytest.raises(ValueError, match="enabled"):
            webhooks_db.update_subscription(
                session, tenant_id=tenant.id, subscription_id=sub.id, changes={"enabled": None}
            )


def test_webhook_patch_explicit_null_description_via_api(env) -> None:
    """The API's exclude_unset=True model_dump correctly distinguishes an
    explicit JSON null from an omitted key end-to-end."""
    _app, client, tokens, _tenant_id = env
    created = client.post(
        "/api/v1/webhooks",
        json={
            "url": "https://hooks.example.com/x",
            "event_types": ["assessment.completed"],
            "description": "will be cleared",
        },
        headers=_bearer(tokens["security_admin"]),
    )
    subscription_id = created.json()["data"]["id"]

    patched = client.patch(
        f"/api/v1/webhooks/{subscription_id}",
        json={"description": None},
        headers=_bearer(tokens["security_admin"]),
    )
    assert patched.status_code == HTTPStatus.OK
    assert patched.json()["data"]["description"] == ""

    omitted = client.patch(
        f"/api/v1/webhooks/{subscription_id}",
        json={"enabled": False},
        headers=_bearer(tokens["security_admin"]),
    )
    assert omitted.status_code == HTTPStatus.OK
    assert omitted.json()["data"]["description"] == ""  # unrelated PATCH left it alone


# --- session ownership: dispatch_event never commits/rolls back the caller's
# transaction (review findings #1/#2) ---------------------------------------


def test_dispatch_event_does_not_commit_the_callers_session(tmp_path: Path) -> None:
    """dispatch_event must not finalize the caller's own not-yet-committed work.

    Simulates the approve_agent_decision shape: the caller has other pending
    work on the same session (an unsaved risk) when it calls dispatch_event;
    if dispatch_event committed the session, that unrelated pending work would
    be durably persisted too, before the caller ever decided to commit it.
    """
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    from security_lakehouse.db import risks as risks_db

    with session_scope(app.state.sessionmaker) as outer_session:
        tenant = create_tenant(outer_session, slug="acme", name="Acme")
        webhooks_db.create_subscription(
            outer_session,
            tenant_id=tenant.id,
            url="https://hooks.example.com/x",
            secret="s3cr3t-value-1234",
            event_types=["assessment.completed"],
        )
        outer_session.commit()

    # A fresh session simulating one request: register unrelated pending work,
    # then dispatch an event on the SAME session, without committing either.
    factory = app.state.sessionmaker
    session = factory()
    try:
        risks_db.create_risk(session, tenant_id=tenant.id, title="unrelated pending work")
        webhook_services.dispatch_event(
            session,
            tenant.id,
            event_type="assessment.completed",
            data={},
            deliver=lambda *a, **k: {"ok": True, "status_code": 200, "attempts": 1, "error": None},
        )
        # Neither the risk nor the delivery has been committed by dispatch_event.
        session.rollback()
    finally:
        session.close()

    with session_scope(app.state.sessionmaker) as verify_session:
        assert risks_db.list_risks(verify_session, tenant_id=tenant.id) == []
        assert webhook_services.list_deliveries(verify_session, tenant.id) == []


def test_dispatch_event_failed_subscription_lookup_does_not_poison_the_session(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A failure listing subscriptions must not leave the caller's session in a
    state where the caller's own later commit fails too (review finding #2).
    """
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        session.commit()

    from security_lakehouse.db import risks as risks_db

    def _boom(session, *, tenant_id, event_type):
        raise RuntimeError("subscription lookup exploded")

    monkeypatch.setattr(webhooks_db, "list_subscriptions_for_event", _boom)

    factory = app.state.sessionmaker
    session = factory()
    try:
        risks_db.create_risk(session, tenant_id=tenant.id, title="pending before the failure")
        results = webhook_services.dispatch_event(session, tenant.id, event_type="assessment.completed", data={})
        assert results == []

        # The caller's own pending work must still be committable -- the
        # savepoint rollback around the failed lookup must not have poisoned
        # the outer transaction.
        session.commit()
    finally:
        session.close()

    with session_scope(app.state.sessionmaker) as verify_session:
        assert len(risks_db.list_risks(verify_session, tenant_id=tenant.id)) == 1


def test_ssrf_refusal_does_not_reveal_the_resolved_address(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(netguard.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.20.30.40", 0))])
    envelope = webhook_delivery.build_envelope(event_type="x", tenant_id="t", occurred_at="now", data={})
    result = webhook_delivery.deliver_webhook(
        "http://internal.example.com/x", secret="s", event_type="x", envelope=envelope
    )
    assert "SSRF" in (result["error"] or "")
    assert "10.20.30.40" not in (result["error"] or "")


def test_redirect_to_a_private_address_does_not_reveal_it(monkeypatch: pytest.MonkeyPatch) -> None:
    def _redirected(request, *, timeout=None, validate=None):
        raise ValueError("webhook resolves to non-public address 192.168.7.9 (SSRF blocked)")

    monkeypatch.setattr(webhook_delivery.netguard, "open_guarded", _redirected)
    envelope = webhook_delivery.build_envelope(event_type="x", tenant_id="t", occurred_at="now", data={})
    result = webhook_delivery.deliver_webhook(
        "https://hooks.example.com/x", secret="s", event_type="x", envelope=envelope, max_retries=0
    )
    assert "SSRF" in (result["error"] or "")
    assert "192.168.7.9" not in (result["error"] or "")


def test_network_errors_report_the_error_class_only(monkeypatch: pytest.MonkeyPatch) -> None:
    def _refused(request, *, timeout=None, validate=None):
        raise urllib.error.URLError("[Errno 111] Connection refused to 172.16.0.5:8443")

    monkeypatch.setattr(webhook_delivery.netguard, "open_guarded", _refused)
    envelope = webhook_delivery.build_envelope(event_type="x", tenant_id="t", occurred_at="now", data={})
    result = webhook_delivery.deliver_webhook(
        "https://hooks.example.com/x", secret="s", event_type="x", envelope=envelope, max_retries=0
    )
    assert result["error"] == "URLError"
