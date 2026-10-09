"""AWS posture-evidence connector runner tests (fixture-backed)."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_lakehouse.connector_runner import CONNECTOR_RAW_FILE, ConnectorSyncError, run_connector_sync
from security_lakehouse.connector_state import (
    append_config_event,
    has_adapter,
    latest_run,
    run_probe,
)
from security_lakehouse.connectors_aws import (
    AWSClient,
    AWSFixtureClient,
    _access_key_event,
    collect_aws_evidence,
    probe_aws_access,
)
from security_lakehouse.io import read_jsonl
from security_lakehouse.validation import validate_raw_events

FIXTURE = Path(__file__).parent / "fixtures" / "aws"
ACCOUNT = "123456789012"


def _by_asset(rows: list[dict], event_type: str) -> dict[str, dict]:
    return {r["entity"]["asset_id"]: r for r in rows if r["event_type"] == event_type}


def test_collect_aws_evidence_is_schema_valid_and_mapped() -> None:
    client = AWSFixtureClient(FIXTURE)
    rows = collect_aws_evidence(
        client,
        account_id=ACCOUNT,
        collected_at=datetime(2026, 5, 28, tzinfo=UTC),
    )

    assert validate_raw_events(rows) == []
    # 3 users -> 3 identity + 3 mfa events; 1 account -> 1 password-policy event.
    assert len(rows) == 7

    identity = _by_asset(rows, "aws.iam.user_access")
    mfa = _by_asset(rows, "aws.iam.mfa_enrollment")
    policy = [r for r in rows if r["event_type"] == "aws.iam.password_policy"]
    assert len(identity) == 3
    assert len(mfa) == 3
    assert len(policy) == 1

    # Every emitted event maps to controls that exist in the catalog.
    for row in rows:
        assert row["source"] == "aws"
        assert "SOC2-CC6.1" in row["controls"]

    # MFA-enrolled user passes; user without an MFA device is a high open finding.
    enrolled = mfa["aws:iam:user/ada-lovelace"]
    assert enrolled["status"] == "pass"
    assert enrolled["severity"] == "info"
    assert enrolled["attributes"]["mfa_enrolled"] is True
    assert enrolled["attributes"]["mfa_device_count"] == 1

    missing = mfa["aws:iam:user/grace-hopper"]
    assert missing["status"] == "open"
    assert missing["severity"] == "high"
    assert missing["attributes"]["needs_mfa"] is True

    # Admin-path principal is surfaced as a high open identity finding for review.
    admin = identity["aws:iam:user/break-glass-admin"]
    assert admin["status"] == "open"
    assert admin["severity"] == "high"
    assert admin["attributes"]["privileged"] is True

    # The weak fixture password policy is an open medium config finding.
    pwd = policy[0]
    assert pwd["entity"]["asset_id"] == f"aws:account:{ACCOUNT}"
    assert pwd["entity"]["asset_type"] == "account_config"
    assert pwd["status"] == "open"
    assert pwd["severity"] == "medium"
    assert pwd["attributes"]["password_policy_strong"] is False
    assert "minimum_password_length_below_14" in pwd["attributes"]["weaknesses"]

    # Asset + evidence shapes are AWS-scoped and point at the read-only ARN.
    sample = identity["aws:iam:user/ada-lovelace"]
    assert sample["entity"]["asset_type"] == "identity_account"
    assert sample["evidence"]["evidence_ref"] == "arn:aws:iam::123456789012:user/ada-lovelace"
    assert pwd["evidence"]["evidence_ref"].endswith(":account-password-policy")


def test_aws_connector_sync_writes_raw_and_materializes_lake(tmp_path: Path) -> None:
    append_config_event(tmp_path, connector_id="aws-posture", state="enabled", actor="alice")
    result = run_connector_sync(
        tmp_path,
        connector_id="aws-posture",
        fixture_dir=FIXTURE,
    )
    assert result.result == "ok"
    assert result.evidence_count == 7
    assert result.materialized is True

    raw_rows = read_jsonl(tmp_path / CONNECTOR_RAW_FILE)
    assert validate_raw_events(raw_rows) == []
    assert len(raw_rows) == 7
    assert all(r["source"] == "aws" for r in raw_rows)
    assert (tmp_path / "bronze" / "raw_events.jsonl").is_file()
    assert (tmp_path / "silver" / "normalized_events.jsonl").is_file()
    assert (tmp_path / "gold" / "current_posture.json").is_file()

    run = latest_run(tmp_path, "aws-posture", kind="sync")
    assert run["result"] == "ok"
    assert run["evidence_count"] == 7


def test_aws_sync_preserves_evidence_refs_and_freshness_source(tmp_path: Path) -> None:
    append_config_event(
        tmp_path,
        connector_id="aws-posture",
        state="enabled",
        actor="alice",
        credentials={"account_id": ACCOUNT},
    )
    run_connector_sync(tmp_path, connector_id="aws-posture", fixture_dir=FIXTURE)

    silver_rows = read_jsonl(tmp_path / "silver" / "normalized_events.jsonl")
    assert silver_rows
    assert all(row["source"] == "aws" for row in silver_rows)
    assert all(row["evidence_ref"] for row in silver_rows)
    assert {row["asset_owner"] for row in silver_rows} == {ACCOUNT}

    freshness_rows = read_jsonl(tmp_path / "gold" / "evidence_freshness.jsonl")
    assert freshness_rows
    assert {row["connector_id"] for row in freshness_rows} == {"aws-posture"}
    assert {row["status"] for row in freshness_rows} == {"fresh"}

    current_posture = json.loads((tmp_path / "gold" / "current_posture.json").read_text(encoding="utf-8"))
    source = current_posture["evidence_freshness"]["sources"][0]
    assert source["source"] == "aws"
    assert source["connector_id"] == "aws-posture"
    assert source["missing_count"] == 0

    violations = current_posture["violations"]
    assert violations
    assert {row["asset_owner"] for row in violations} == {ACCOUNT}

    assets = read_jsonl(tmp_path / "gold" / "asset_risk.jsonl")
    assert assets
    assert {row["asset_owner"] for row in assets} == {ACCOUNT}


def test_aws_connector_sync_upserts_stable_event_ids(tmp_path: Path) -> None:
    append_config_event(tmp_path, connector_id="aws-posture", state="enabled", actor="a")
    first = run_connector_sync(tmp_path, connector_id="aws-posture", fixture_dir=FIXTURE)
    second = run_connector_sync(
        tmp_path,
        connector_id="aws-posture",
        fixture_dir=FIXTURE,
        materialize=False,
    )
    assert first.evidence_count == second.evidence_count == 7
    assert len(read_jsonl(tmp_path / CONNECTOR_RAW_FILE)) == 7


def test_aws_connector_sync_requires_enabled_connector(tmp_path: Path) -> None:
    with pytest.raises(ConnectorSyncError, match="not enabled") as exc:
        run_connector_sync(tmp_path, connector_id="aws-posture", fixture_dir=FIXTURE)
    assert exc.value.run["result"] == "error"


def test_aws_connector_sync_without_fixture_or_creds_errors(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("AWS_ACCOUNT_ID", raising=False)
    append_config_event(tmp_path, connector_id="aws-posture", state="enabled", actor="a")
    with pytest.raises(ConnectorSyncError, match="requires --fixture-dir"):
        run_connector_sync(tmp_path, connector_id="aws-posture")


def test_aws_adapter_runs_live_probe_before_enable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert has_adapter("aws-posture") is True
    # Before enablement the probe is skipped (no synthetic collection signal).
    skipped = run_probe(tmp_path, connector_id="aws-posture")
    assert skipped["result"] == "skipped"
    assert "not enabled" in skipped["error"]

    def fake_probe(*, credentials: dict, options: dict, **_kwargs: object) -> dict:
        assert credentials["role_arn"].endswith(":role/GrcLakePostureReadOnlyRole")
        assert credentials["external_id"] == "tenant-binding"
        assert options["region"] == "us-east-1"
        return {"ok": True, "account_id": ACCOUNT, "capabilities": ["iam:ListUsers"]}

    monkeypatch.setattr("security_lakehouse.connector_state.probe_aws_access", fake_probe)
    ok = run_probe(
        tmp_path,
        connector_id="aws-posture",
        credentials={
            "account_id": ACCOUNT,
            "role_arn": f"arn:aws:iam::{ACCOUNT}:role/GrcLakePostureReadOnlyRole",
            "external_id": "tenant-binding",
        },
        options={"region": "us-east-1"},
    )
    assert ok["result"] == "ok"
    assert ok["metadata"]["probe_mode"] == "live"
    assert ok["metadata"]["capabilities"] == ["iam:ListUsers"]


def test_aws_adapter_records_safe_error_when_live_probe_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def denied_probe(*, credentials: dict, options: dict, **_kwargs: object) -> dict:
        raise RuntimeError("credential detail that must not be persisted")

    monkeypatch.setattr(
        "security_lakehouse.connector_state.probe_aws_access",
        denied_probe,
    )
    rec = run_probe(
        tmp_path,
        connector_id="aws-posture",
        credentials={
            "account_id": ACCOUNT,
            "role_arn": f"arn:aws:iam::{ACCOUNT}:role/GrcLakePostureReadOnlyRole",
        },
        options={},
    )
    assert rec["result"] == "error"
    assert rec["error"] == "RuntimeError"
    assert "credential detail" not in json.dumps(rec)


def test_aws_adapter_records_bounded_provider_error_when_sts_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class ClientError(Exception):
        response = {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Not authorized to perform sts:AssumeRole",
            }
        }

    def denied_probe(*, credentials: dict, options: dict, **_kwargs: object) -> dict:
        raise ClientError("raw sdk text that should not be used")

    monkeypatch.setattr("security_lakehouse.connector_state.probe_aws_access", denied_probe)
    rec = run_probe(
        tmp_path,
        connector_id="aws-posture",
        credentials={"account_id": ACCOUNT, "role_arn": f"arn:aws:iam::{ACCOUNT}:role/GrcLakePostureReadOnlyRole"},
        options={},
    )

    assert rec["result"] == "error"
    assert rec["error"] == "ClientError: AccessDenied: Not authorized to perform sts:AssumeRole"
    assert "raw sdk text" not in json.dumps(rec)


def test_probe_aws_access_uses_assumed_role_and_read_permission(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, object] = {}

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            calls["init"] = kwargs

        def caller_identity(self) -> dict:
            calls["caller_identity"] = True
            return {"Account": ACCOUNT}

        def users(self) -> list[dict]:
            calls["users"] = True
            return [{"UserName": "one"}, {"UserName": "two"}]

    monkeypatch.setattr("security_lakehouse.connectors_aws.AWSClient", FakeClient)
    result = probe_aws_access(
        credentials={
            "account_id": ACCOUNT,
            "role_arn": f"arn:aws:iam::{ACCOUNT}:role/GrcLakePostureReadOnlyRole",
            "external_id": "tenant-binding",
        },
        options={"region": "us-east-1"},
    )

    assert calls["init"] == {
        "region_name": "us-east-1",
        "role_arn": f"arn:aws:iam::{ACCOUNT}:role/GrcLakePostureReadOnlyRole",
        "external_id": "tenant-binding",
    }
    assert calls["caller_identity"] is True
    assert calls["users"] is True
    assert result == {
        "ok": True,
        "account_id": ACCOUNT,
        "credential_mode": "assume_role",
        "role_arn": f"arn:aws:iam::{ACCOUNT}:role/GrcLakePostureReadOnlyRole",
        "capabilities": ["sts:AssumeRole", "sts:GetCallerIdentity", "iam:ListUsers"],
        "principal_count": 2,
    }


class _FakeBoto3:
    """Minimal boto3 stand-in to exercise AWSClient auth modes offline."""

    def __init__(self) -> None:
        self.assume_calls: list[dict] = []
        self.iam_from = ""  # "client" (ambient) or "session" (assumed)
        self.session_creds: dict | None = None
        self.session_services: list[tuple[str, str | None]] = []

    def client(self, service: str, region_name=None):  # noqa: ANN001
        if service == "sts":
            outer = self

            class _STS:
                def assume_role(self, **kwargs):  # noqa: ANN003
                    outer.assume_calls.append(kwargs)
                    return {
                        "Credentials": {
                            "AccessKeyId": "ASIA_TMP",
                            "SecretAccessKey": "secret_tmp",
                            "SessionToken": "token_tmp",
                        }
                    }

            return _STS()
        if service == "iam":
            self.iam_from = "client"
            return SimpleNamespace(get_paginator=lambda *_a, **_k: None)
        raise AssertionError(f"unexpected client {service}")

    def Session(self, **creds):  # noqa: N802, ANN003
        self.session_creds = creds
        outer = self

        class _Session:
            def client(self, service: str, region_name=None):  # noqa: ANN001
                outer.session_services.append((service, region_name))
                if service == "iam":
                    outer.iam_from = "session"
                return SimpleNamespace(get_paginator=lambda *_a, **_k: None)

        return _Session()


def test_aws_client_assumes_role_with_external_id(monkeypatch: pytest.MonkeyPatch) -> None:
    # The hosted-GRC connect model: hand GRC Lake a Role ARN + External ID and it
    # assumes the read-only role via STS — no static key, no ambient identity.
    fake = _FakeBoto3()
    monkeypatch.setitem(sys.modules, "boto3", fake)

    AWSClient(role_arn="arn:aws:iam::123456789012:role/GrcLakePostureReadOnlyRole", external_id="ext-secret-123")

    assert len(fake.assume_calls) == 1
    call = fake.assume_calls[0]
    assert call["RoleArn"].endswith(":role/GrcLakePostureReadOnlyRole")
    assert call["ExternalId"] == "ext-secret-123"
    assert call["RoleSessionName"] == "trustops-posture"
    # IAM client is built from the assumed short-lived session, not ambient.
    assert fake.iam_from == "session"
    assert fake.session_creds["aws_session_token"] == "token_tmp"


def test_aws_inventory_clients_share_the_assumed_session(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeBoto3()
    monkeypatch.setitem(sys.modules, "boto3", fake)
    client = AWSClient(
        role_arn="arn:aws:iam::123456789012:role/GrcLakePostureReadOnlyRole",
        external_id="ext-secret-123",
    )

    for service in ("ec2", "s3", "rds", "cloudtrail", "config", "securityhub", "organizations"):
        client.service_client(service, region_name="us-west-2")

    assert len(fake.assume_calls) == 1
    assert {(service, region) for service, region in fake.session_services} >= {
        (service, "us-west-2")
        for service in ("ec2", "s3", "rds", "cloudtrail", "config", "securityhub", "organizations")
    }


def test_aws_role_template_covers_selected_inventory_services() -> None:
    template = (Path(__file__).parents[1] / "deploy/aws/grc-lake-posture-readonly-role.yaml").read_text(
        encoding="utf-8"
    )
    for action in (
        "ec2:DescribeInstances",
        "s3:ListAllMyBuckets",
        "rds:DescribeDBInstances",
        "cloudtrail:DescribeTrails",
        "config:DescribeConfigurationRecorders",
        "securityhub:DescribeHub",
        "organizations:DescribeOrganization",
    ):
        assert action in template


def test_selected_aws_inventory_is_normalized_and_partial_failures_are_isolated() -> None:
    class InventoryClient:
        def inventory(self, service: str, *, region_name: str) -> list[dict]:
            if service == "rds":
                raise RuntimeError("RDS is unavailable")
            if service == "ec2":
                return [{"id": "i-123", "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-123", "state": "running"}]
            return []

    from security_lakehouse.connectors_aws import collect_aws_inventory_evidence

    rows = collect_aws_inventory_evidence(
        InventoryClient(),
        account_id=ACCOUNT,
        regions=["us-east-1"],
        services=["ec2", "rds"],
        collected_at=datetime(2026, 5, 28, tzinfo=UTC),
    )

    assert validate_raw_events(rows) == []
    # The denied service no longer vanishes silently: it lands as a coverage gap.
    assert [row["event_type"] for row in rows] == ["aws.inventory.ec2", "aws.collection_gap"]
    assert rows[0]["entity"]["asset_id"] == "aws:ec2:us-east-1:i-123"
    assert rows[0]["attributes"]["region"] == "us-east-1"
    assert rows[1]["attributes"]["message"] == "AWS rds inventory in us-east-1 was not collected (read failed)"
    assert "RDS is unavailable" not in json.dumps(rows)


def test_global_inventory_gap_clears_when_a_later_region_succeeds() -> None:
    from security_lakehouse.connectors_aws import collect_aws_inventory_evidence

    class InventoryClient:
        def inventory(self, service: str, *, region_name: str) -> list[dict]:
            if region_name == "us-east-1":
                raise RuntimeError("regional endpoint unavailable")
            return [{"id": "bucket-a"}]

    rows = collect_aws_inventory_evidence(
        InventoryClient(),
        account_id=ACCOUNT,
        regions=["us-east-1", "us-west-2"],
        services=["s3"],
        collected_at=datetime(2026, 5, 28, tzinfo=UTC),
    )
    assert [row["event_type"] for row in rows] == ["aws.inventory.s3"]


def test_aws_client_uses_ambient_chain_without_role_arn(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeBoto3()
    monkeypatch.setitem(sys.modules, "boto3", fake)

    AWSClient()

    # No assume-role call; IAM client comes straight from the provider chain.
    assert fake.assume_calls == []
    assert fake.iam_from == "client"


def test_mfa_finding_only_applies_to_console_users(tmp_path: Path) -> None:
    # MFA is a console (human) control. A key-only service identity with no login
    # profile must not be flagged for "no MFA"; only a console user is.
    fixture = tmp_path / "aws"
    fixture.mkdir()
    (fixture / "iam_users.json").write_text(
        json.dumps(
            [
                {"UserName": "human-admin", "Arn": f"arn:aws:iam::{ACCOUNT}:user/human-admin"},
                {"UserName": "svc-scanner", "Arn": f"arn:aws:iam::{ACCOUNT}:user/svc-scanner"},
            ]
        ),
        encoding="utf-8",
    )
    (fixture / "mfa_devices.json").write_text(json.dumps({"human-admin": [], "svc-scanner": []}), encoding="utf-8")
    # Only the human has a console login profile.
    (fixture / "login_profiles.json").write_text(json.dumps(["human-admin"]), encoding="utf-8")

    rows = collect_aws_evidence(AWSFixtureClient(fixture), account_id=ACCOUNT)
    assert validate_raw_events(rows) == []
    mfa = {r["attributes"]["user_name"]: r for r in rows if r["event_type"] == "aws.iam.mfa_enrollment"}

    # Console user without MFA -> high open finding.
    assert mfa["human-admin"]["status"] == "open"
    assert mfa["human-admin"]["severity"] == "high"
    assert mfa["human-admin"]["attributes"]["needs_mfa"] is True
    assert mfa["human-admin"]["attributes"]["console_access"] is True
    assert mfa["human-admin"]["attributes"]["identity_type"] == "human"

    # Service identity (no console login) -> not a finding; MFA marked N/A.
    assert mfa["svc-scanner"]["status"] == "observed"
    assert mfa["svc-scanner"]["severity"] == "info"
    assert mfa["svc-scanner"]["attributes"]["needs_mfa"] is False
    assert mfa["svc-scanner"]["attributes"]["console_access"] is False
    assert mfa["svc-scanner"]["attributes"]["mfa_not_applicable"] is True
    assert mfa["svc-scanner"]["attributes"]["identity_type"] == "service"


def test_aws_client_console_access_reads_login_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    # GetLoginProfile success => console user; NoSuchEntity (raises) => programmatic.
    class _IAM:
        def get_login_profile(self, *, UserName: str):  # noqa: N803
            if UserName == "human":
                return {"LoginProfile": {"UserName": "human"}}
            # Model botocore's ClientError shape so the client's code-based
            # NoSuchEntity check (not a bare exception type) recognizes it.
            err = RuntimeError("NoSuchEntity")
            err.response = {"Error": {"Code": "NoSuchEntity"}}  # type: ignore[attr-defined]
            raise err

    client = AWSClient.__new__(AWSClient)
    client._iam = _IAM()
    assert client.console_access("human") is True
    assert client.console_access("svc") is False


def test_access_key_hygiene_flags_stale_service_account_keys(tmp_path: Path) -> None:
    # For a service identity (no console / no MFA) the relevant control is key
    # rotation, not MFA: a stale active access key is the open finding.
    fixture = tmp_path / "aws"
    fixture.mkdir()
    (fixture / "iam_users.json").write_text(
        json.dumps([{"UserName": "svc-scanner", "Arn": f"arn:aws:iam::{ACCOUNT}:user/svc-scanner"}]),
        encoding="utf-8",
    )
    (fixture / "mfa_devices.json").write_text(json.dumps({"svc-scanner": []}), encoding="utf-8")
    (fixture / "login_profiles.json").write_text(json.dumps([]), encoding="utf-8")  # programmatic
    (fixture / "access_keys.json").write_text(
        json.dumps(
            {"svc-scanner": [{"AccessKeyId": "AKIASTALE", "Status": "Active", "CreateDate": "2024-01-01T00:00:00Z"}]}
        ),
        encoding="utf-8",
    )

    rows = collect_aws_evidence(
        AWSFixtureClient(fixture), account_id=ACCOUNT, collected_at=datetime(2026, 6, 27, tzinfo=UTC)
    )
    assert validate_raw_events(rows) == []

    key_events = [r for r in rows if r["event_type"] == "aws.iam.access_key_hygiene"]
    assert len(key_events) == 1
    ev = key_events[0]
    assert ev["status"] == "open"
    assert ev["severity"] == "medium"
    assert ev["attributes"]["identity_type"] == "service"
    assert ev["attributes"]["stale_key"] is True
    assert ev["attributes"]["oldest_active_key_age_days"] > 90

    # The missing-MFA event is not a finding or passing evidence for this service identity.
    mfa = next(r for r in rows if r["event_type"] == "aws.iam.mfa_enrollment")
    assert mfa["status"] == "observed"


def test_access_key_hygiene_passes_on_fresh_single_key(tmp_path: Path) -> None:
    fixture = tmp_path / "aws"
    fixture.mkdir()
    (fixture / "iam_users.json").write_text(
        json.dumps([{"UserName": "svc-fresh", "Arn": f"arn:aws:iam::{ACCOUNT}:user/svc-fresh"}]), encoding="utf-8"
    )
    (fixture / "access_keys.json").write_text(
        json.dumps(
            {"svc-fresh": [{"AccessKeyId": "AKIAFRESH", "Status": "Active", "CreateDate": "2026-06-01T00:00:00Z"}]}
        ),
        encoding="utf-8",
    )
    rows = collect_aws_evidence(
        AWSFixtureClient(fixture), account_id=ACCOUNT, collected_at=datetime(2026, 6, 27, tzinfo=UTC)
    )
    key = next(r for r in rows if r["event_type"] == "aws.iam.access_key_hygiene")
    assert key["status"] == "pass"
    assert key["attributes"]["stale_key"] is False


def test_active_access_key_with_unparseable_date_flags_rotation() -> None:
    """An active key whose CreateDate can't be parsed must not score a false pass."""
    event = _access_key_event(
        ACCOUNT,
        "svc-user",
        {"UserName": "svc-user"},
        [{"Status": "Active", "CreateDate": "not-a-real-date"}],
        datetime(2026, 1, 1, tzinfo=UTC),
        "tenant-x",
    )
    assert event["status"] == "open"
    assert event["attributes"]["stale_key"] is True
    assert event["attributes"]["needs_rotation"] is True


class _FakeClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class _RaisingIam:
    def __init__(self, code: str) -> None:
        self._code = code

    def get_account_password_policy(self):  # noqa: ANN201
        raise _FakeClientError(self._code)

    def get_login_profile(self, **_kwargs):  # noqa: ANN003, ANN201
        raise _FakeClientError(self._code)


def _client_with_iam(code: str) -> AWSClient:
    client = AWSClient.__new__(AWSClient)  # bypass boto3 in __init__
    client._iam = _RaisingIam(code)  # type: ignore[attr-defined]  # noqa: SLF001
    return client


def test_password_policy_swallows_only_nosuchentity() -> None:
    assert _client_with_iam("NoSuchEntity").password_policy() == {}
    with pytest.raises(_FakeClientError):
        _client_with_iam("Throttling").password_policy()


def test_console_access_swallows_only_nosuchentity() -> None:
    assert _client_with_iam("NoSuchEntity").console_access("svc-user") is False
    with pytest.raises(_FakeClientError):
        _client_with_iam("AccessDenied").console_access("svc-user")
