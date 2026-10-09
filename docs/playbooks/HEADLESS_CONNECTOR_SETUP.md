# Headless Connector Setup

Connect read-only sources, validate access, enable collection, sync evidence, and
run control evaluation **without the console** — using the same probe-gated contract
as the UI, MCP, and scheduler.

## Default path (most teams)

You do **not** need a customer security data lake first. Use **direct read-only API
connectors** — the same agentless model as typical GRC SaaS:

```text
GitHub · AWS · Azure · GCP · Okta · Google Workspace · Jira · GitLab
  → probe → enable → sync → eval
```

Snowflake, ClickHouse, object storage, and SIEM connectors are **optional** — only
when you already materialize evidence in those stores.

## Prerequisites

- Running GRC Lake server (`grc-lake serve --server`) or local lake + CLI
- API key with `connector_manage` scope (or `--allow-insecure-no-auth` for local dev)
- Read-only credentials staged in your secret manager (env var **names** only — never paste raw secrets into GRC Lake)

Set:

```bash
export GRC_LAKE_API_URL="http://127.0.0.1:8787"
export GRC_LAKE_API_KEY="tok_…"   # security_admin or connector_manage
export CORR="setup-$(date +%s)"
```

## GitHub Security (direct API)

### REST (curl)

```bash
# 1. Probe — validates credential ref + repo scope
curl -sS -X POST "$GRC_LAKE_API_URL/api/v1/connectors/github-security/probe" \
  -H "Authorization: Bearer $GRC_LAKE_API_KEY" \
  -H "Content-Type: application/json" \
  -H "X-Correlation-ID: $CORR" \
  -d '{
    "actor": "ci",
    "credentials": {"credential_ref": "GRC_LAKE_GITHUB_APP_INSTALLATION_TOKEN"},
    "options": {"repo": "acme/platform"}
  }' | jq .

# 2. Enable — rejected until probe ok + matching fingerprint
curl -sS -X POST "$GRC_LAKE_API_URL/api/v1/connectors/github-security/configure" \
  -H "Authorization: Bearer $GRC_LAKE_API_KEY" \
  -H "Content-Type: application/json" \
  -H "X-Correlation-ID: $CORR" \
  -d '{
    "state": "enabled",
    "actor": "ci",
    "credentials": {"credential_ref": "GRC_LAKE_GITHUB_APP_INSTALLATION_TOKEN"},
    "options": {"repo": "acme/platform"}
  }' | jq .

# 3. Sync — lands raw evidence (idempotent on event_id)
curl -sS -X POST "$GRC_LAKE_API_URL/api/v1/connectors/github-security/sync" \
  -H "Authorization: Bearer $GRC_LAKE_API_KEY" \
  -H "Content-Type: application/json" \
  -H "X-Correlation-ID: $CORR" \
  -d '{"actor": "ci"}' | jq .

# 4. Control eval — materialize posture from lake
curl -sS -X POST "$GRC_LAKE_API_URL/api/v1/ingestion/eval" \
  -H "Authorization: Bearer $GRC_LAKE_API_KEY" \
  -H "Content-Type: application/json" \
  -H "X-Correlation-ID: $CORR" \
  -d '{"actor": "ci"}' | jq .

# 5. Verify posture
curl -sS "$GRC_LAKE_API_URL/api/v1/posture/current" \
  -H "Authorization: Bearer $GRC_LAKE_API_KEY" | jq .
```

### CLI (local lake)

```bash
LAKE=build/lakehouse

grc-lake connectors probe \
  --lake "$LAKE" \
  --connector-id github-security \
  --credentials-json '{"credential_ref":"GRC_LAKE_GITHUB_APP_INSTALLATION_TOKEN"}' \
  --options-json '{"repo":"acme/platform"}'

grc-lake connectors configure \
  --lake "$LAKE" \
  --connector-id github-security \
  --state enabled \
  --credentials-json '{"credential_ref":"GRC_LAKE_GITHUB_APP_INSTALLATION_TOKEN"}' \
  --options-json '{"repo":"acme/platform"}'

grc-lake connectors sync \
  --lake "$LAKE" \
  --connector-id github-security

grc-lake pipeline eval --lake "$LAKE"
```

### MCP (remote server mode)

Prefer `GRC_LAKE_API_URL` + `GRC_LAKE_API_KEY` so writes are RBAC-gated:

1. `probe_connector` — `github-security`, credentials + options
2. `configure_connector` — `state: enabled`
3. `sync_connector`
4. `run_lake_eval`
5. `get_posture`

Use `describe_api` to list the full tool catalog.

## AWS Posture (direct API)

Discovery is account-scoped:

```bash
curl -sS -X POST "$GRC_LAKE_API_URL/api/v1/connectors/aws-posture/discover" \
  -H "Authorization: Bearer $GRC_LAKE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"credentials": {"account_id": "123456789012"}, "options": {"region": "us-east-1"}}' | jq .

curl -sS -X POST "$GRC_LAKE_API_URL/api/v1/connectors/aws-posture/probe" \
  -H "Authorization: Bearer $GRC_LAKE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"credentials": {"account_id": "123456789012", "role_arn": "arn:aws:iam::123456789012:role/GrcLakePostureReadOnlyRole", "external_id": "<external-id>"}, "options": {"region": "us-east-1"}}' | jq .
```

Over the API the AWS probe always assumes `role_arn`; the local credential chain
(`AWS_PROFILE`, SSO) is accepted only by the local CLI probe. See
[LIVE_CLOUD_POC.md](../LIVE_CLOUD_POC.md#aws-trial-account).

Then configure → sync → eval as above.

## Optional: existing evidence lake

If your team already runs a governed Snowflake or ClickHouse evidence store:

1. Provision a read-only service identity (SELECT on audit views only).
2. `connectors discover` → choose warehouse/database/schema.
3. Probe → enable → sync reads **views you already maintain** — GRC Lake does not
   replace your SDL pipeline; it evaluates controls over what is already there.

See [LIVE_CLOUD_POC.md](../LIVE_CLOUD_POC.md) for Snowflake key-pair setup.

## Scheduler (continuous)

Production: run `grc-lake scheduler tick` on a CronJob. It fires due
connector syncs and eval schedules without console interaction.

```bash
curl -sS -X POST "$GRC_LAKE_API_URL/api/v1/scheduler/tick" \
  -H "Authorization: Bearer $GRC_LAKE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{}' | jq .
```

## Troubleshooting

| Symptom                                   | Fix                                                             |
| ----------------------------------------- | --------------------------------------------------------------- |
| `configure` returns 400 “Test connection” | Run `probe` first with the same credentials + options           |
| `403 requires scope: connector_manage`    | Use `security_admin` API key or role with connector_manage      |
| Sync ok but posture empty                 | Run `POST /api/v1/ingestion/eval` or `pipeline eval`            |
| Probe ok, enable still blocked            | Credential fingerprint mismatch — re-probe after changing scope |

## Related

- [HEADLESS_GRC.md](../HEADLESS_GRC.md) — agent-first architecture
- [CONNECTORS.md](../CONNECTORS.md) — catalog and access boundaries
- [CONTINUOUS_INGESTION.md](../CONTINUOUS_INGESTION.md) — scheduler and idempotency
- [api/AGENT_API.md](../api/AGENT_API.md) — full `/api/v1` reference
