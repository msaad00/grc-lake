# Connector And Access Model

TrustOps should collect evidence with the smallest viable access boundary.

For ingestion idempotency, unique event IDs, headless/agent vs console surfaces,
and security-finding flow, see
[INGESTION_CONNECTORS_IDEMPOTENCY.md](INGESTION_CONNECTORS_IDEMPOTENCY.md).

## Default path (most teams)

**No customer security data lake required.** Connect read-only to source systems
(GitHub, AWS, Okta, …), sync evidence into TrustOps's assessment store, then run
control evaluation:

```text
discover scope → probe → enable → sync → eval
```

This is the same agentless model as typical GRC SaaS — scoped tokens and
read-only roles, not agents or broad cloud admin. TrustOps keeps the assessment
store in **your** boundary (`/lake` volume or self-hosted storage), not an opaque
vendor database.

Headless setup (curl, CLI, MCP): [playbooks/HEADLESS_CONNECTOR_SETUP.md](playbooks/HEADLESS_CONNECTOR_SETUP.md).

## Access modes (pick one)

| Mode                             | When to use                                                            | Boundary                          |
| -------------------------------- | ---------------------------------------------------------------------- | --------------------------------- |
| **Direct tool API read**         | **Default** — no existing evidence lake                                | scoped token or app installation  |
| Existing security data lake read | You already run a lake or SIEM export ([BYOL](BRING_YOUR_OWN_LAKE.md)) | read-only role                    |
| Managed evidence objects         | Local proof, starter deployments, demos                                | dedicated schema/output directory |

Avoid broad cloud permissions. Connectors should not need admin, delete, owner,
or unrestricted write access to evaluate posture.

## Production Hero Paths

| Store      | Role                                                | Connector                   |
| ---------- | --------------------------------------------------- | --------------------------- |
| Snowflake  | governed evidence, audit views, retention, RBAC     | `snowflake-evidence-lake`   |
| ClickHouse | telemetry, runtime events, trends, fast aggregation | `clickhouse-telemetry-lake` |

## Catalog

The connector catalog is versioned in:

```text
connectors/catalog.json
```

Validate it with:

```bash
security-lakehouse connectors validate
```

Each catalog entry also carries **UX metadata** consumed by the console and demo kit:

| Field         | Purpose                                                                        |
| ------------- | ------------------------------------------------------------------------------ |
| `vendor`      | Short vendor label (AWS, GitHub, Snowflake, …)                                 |
| `description` | What evidence the connector ingests                                            |
| `setup_hint`  | Read-only connection guidance shown in `/connectors` and account-linking cards |

`release_stage` is optional: `"preview"` marks an implemented connector that has not
been verified against a live tenant (the console shows a Preview badge); absent or
`"ga"` means generally available. `security-lakehouse connectors validate` rejects any
other value.

Connection field definitions live in `app/web/src/lib/connector-forms.ts`; vendor
marks use neutral text badges in `app/web/src/lib/connector-visuals.ts` (not
official logos — see [THIRD_PARTY_ASSETS.md](THIRD_PARTY_ASSETS.md)).

For live Azure, AWS, or Snowflake trials, use the least-privilege runbook in
[`docs/LIVE_CLOUD_POC.md`](LIVE_CLOUD_POC.md). It keeps first-run access
read-only and avoids passwords, human-scoped developer tokens, root keys, and
broad cloud credentials.

For production operation, use
[`docs/CONTINUOUS_INGESTION.md`](CONTINUOUS_INGESTION.md). It describes the
customer-owned identity boundary, probe-gated enablement, scheduler loop,
idempotent raw upserts, API limits, error behavior, and snapshot integrity.

List configured connector contracts:

```bash
security-lakehouse connectors list
```

## Connector Runner

TrustOps currently has **28 connector contracts**. **Twenty-five** are executable
runners (direct source/API runners, the Snowflake, Databricks, ClickHouse,
Iceberg/Parquet, BigQuery, S3, SIEM, and runtime-gateway existing-lake readers, and
the Okta System Log incremental adapter). The remaining entries are read-only access contracts or managed evidence
boundaries — probes validate configuration but **sync is not available** until a
collection adapter ships. Runners marked **(preview)** carry
`"release_stage": "preview"` in the catalog and a Preview badge in `/connectors`:
they are implemented and fixture-tested against the vendor's documented API but
have not yet been verified against a live tenant.

| Connector ID                | Source                  | Runner status                           |
| --------------------------- | ----------------------- | --------------------------------------- |
| `github-security`           | GitHub repo security    | executable                              |
| `gitlab-security`           | GitLab repo security    | executable                              |
| `aws-posture`               | AWS IAM/posture         | executable                              |
| `okta-identity`             | Okta identity/MFA       | executable                              |
| `google-workspace-identity` | Google Workspace users  | executable                              |
| `gcp-posture`               | GCP IAM/posture         | executable                              |
| `azure-posture`             | Azure IAM/posture       | executable                              |
| `jira-ticketing`            | Jira tickets/workflows  | executable                              |
| `intune-devices`            | Intune device posture   | executable                              |
| `bamboohr-personnel`        | BambooHR employment     | executable                              |
| `rippling-personnel`        | Rippling employment     | executable                              |
| `workday-personnel`         | Workday employment      | executable (RaaS report)                |
| `databricks-evidence-lake`  | Databricks UC evidence  | executable existing-lake read (preview) |
| `jamf-devices`              | Jamf Pro device posture | executable (preview)                    |
| `crowdstrike-falcon`        | CrowdStrike Falcon EDR  | executable (preview)                    |
| `kubernetes-cluster`        | Kubernetes config       | executable (preview)                    |
| `knowbe4-training`          | KnowBe4 training        | executable (preview)                    |
| `snowflake-evidence-lake`   | governed evidence lake  | executable existing-lake read           |
| `clickhouse-telemetry-lake` | telemetry analytics     | executable existing-lake read           |
| `iceberg-parquet-lake`      | Iceberg / Parquet lake  | executable existing-lake read (preview) |
| `bigquery-evidence-lake`    | BigQuery evidence       | executable existing-lake read (preview) |
| `object-storage-evidence`   | object evidence store   | executable existing-lake read           |
| `okta-system-log`           | Okta System Log API     | **implemented** (incremental)           |
| `siem-alerts`               | SIEM/detection exports  | executable existing-lake read           |
| `runtime-gateway`           | runtime policy events   | executable existing-lake read           |
| `identity-provider`         | generic identity source | **contract only** (no sync)             |
| `ticketing`                 | generic ticketing       | **contract only** (no sync)             |
| `managed-local-evidence`    | local starter evidence  | managed evidence object                 |

Every executable runner writes valid raw evidence into:

```text
<lake>/raw/connector_events.jsonl
```

The production lifecycle is intentionally the same for UI, API, CLI, scheduler,
and agents:

1. create a scoped source role, app, or service identity,
2. discover the read scope visible to that identity,
3. probe the exact credential reference and scope,
4. enable only after the probe succeeds,
5. sync manually or by schedule.

### AWS multi-account scale

AWS posture uses the same third-party role pattern for one account or hundreds:

| Item          | Scaling rule                                                                                                                            |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Rollout       | Use **CloudFormation StackSets** or **Terraform workspaces** to deploy the same read-only role across target AWS accounts.              |
| Authorization | The deployed role trusts the TrustOps runtime principal and constrains access with External ID.                                         |
| External ID   | Use **one External ID per deployed role**; TrustOps includes that exact value in STS AssumeRole.                                        |
| Confirmation  | Default role names can be confirmed by AWS account ID; custom role names use the Role ARN output.                                       |
| Scale surface | **Bulk account import** is the follow-up console/API surface for registering many deployed roles after rollout.                         |
| Sync          | The scheduled sync assumes each registered role, receives short-lived session credentials, and reads only the granted IAM posture APIs. |
| Evaluation    | Raw evidence keeps the AWS account ID attached; deterministic controls evaluate across the combined evidence set.                       |

<p align="center">
  <img src="images/trustops-readonly-connections.svg" alt="Read-only connector model: AWS IAM role, GitHub App, Okta token, Snowflake SELECT into TrustOps ingestion" width="100%">
</p>

Mermaid diagrams: [connector-ingestion.md](diagrams/connector-ingestion.md)

Do not paste passwords, human-scoped developer tokens, root keys, or private
keys into TrustOps. Use SSO, an assumable role, OAuth, key-pair auth, or a
secret-manager reference. TrustOps records a non-secret fingerprint so a later
enable action must match the probed access payload.

Probe and enable a fixture-backed GitHub connector:

```bash
security-lakehouse connectors probe \
  --lake build/lakehouse \
  --connector-id github-security \
  --credentials-json '{"token":"fixture-read-token"}' \
  --options-json '{"org":"acme"}'

security-lakehouse connectors configure \
  --lake build/lakehouse \
  --connector-id github-security \
  --state enabled \
  --credentials-json '{"token":"fixture-read-token"}' \
  --options-json '{"org":"acme"}'

security-lakehouse connectors sync \
  --lake build/lakehouse \
  --connector-id github-security \
  --repo OWNER/REPO \
  --fixture-dir tests/fixtures/github-governance
```

For live GitHub collection, use a GitHub App installation token from the
selected environment variable or secret manager. The configure payload should
store the reference name, not the raw token:

The minimum GitHub App repository permissions are:

| Permission                   | Access unlocked                                                            |
| ---------------------------- | -------------------------------------------------------------------------- |
| Metadata: read               | Repository identity, visibility, and default branch                        |
| Administration: read         | Branch protection, collaborators, teams, and Actions workflow defaults     |
| Code scanning alerts: read   | Aggregate code-scanning counts by state and severity                       |
| Secret scanning alerts: read | Aggregate secret-scanning counts by state; alert details are not persisted |
| Dependabot alerts: read      | Aggregate dependency-alert counts by state and severity                    |

TrustOps follows GitHub list pagination for these alert APIs, capped at 1,000
records per category per sync. It persists aggregate counts only; alert payloads,
secret material, and tokens are not copied into evidence.

```bash
security-lakehouse connectors probe \
  --lake build/lakehouse \
  --connector-id github-security \
  --credentials-json '{"credential_ref":"TRUSTOPS_GITHUB_APP_INSTALLATION_TOKEN"}' \
  --options-json '{"repo":"OWNER/REPO"}'

security-lakehouse connectors configure \
  --lake build/lakehouse \
  --connector-id github-security \
  --state enabled \
  --credentials-json '{"credential_ref":"TRUSTOPS_GITHUB_APP_INSTALLATION_TOKEN"}' \
  --options-json '{"repo":"OWNER/REPO"}'

TRUSTOPS_GITHUB_APP_INSTALLATION_TOKEN=... security-lakehouse connectors sync \
  --lake build/lakehouse \
  --connector-id github-security \
  --repo OWNER/REPO
```

GitLab governance sync (fixture-backed or live token):

```bash
security-lakehouse connectors sync \
  --lake build/lakehouse \
  --connector-id gitlab-security \
  --repo GROUP/PROJECT \
  --fixture-dir tests/fixtures/gitlab-governance

TRUSTOPS_GITLAB_ACCESS_TOKEN=... security-lakehouse connectors sync \
  --lake build/lakehouse \
  --connector-id gitlab-security \
  --repo GROUP/PROJECT
```

Self-managed GitLab: set `TRUSTOPS_GITLAB_API_URL` to your instance API base
(for example `https://gitlab.example.com/api/v4`) before sync.

Snowflake is the read-existing-lake path. The fixture path mirrors the expected
views (`audit_events`, `control_posture`, `asset_risk`, and
`evidence_bundles`) and exercises the same raw-to-gold pipeline:

```bash
security-lakehouse connectors probe \
  --lake build/lakehouse \
  --connector-id snowflake-evidence-lake \
  --credentials-json '{"account":"fixture","user":"trustops_reader","credential_ref":"fixture-sso"}' \
  --options-json '{"warehouse":"TRUSTOPS_READ_WH","database":"TRUSTOPS_SECURITY_LAKE","schema":"EVIDENCE","audit_events":"TRUSTOPS_AUDIT_EVENTS","control_posture":"TRUSTOPS_CONTROL_POSTURE","asset_risk":"TRUSTOPS_ASSET_RISK","evidence_bundles":"TRUSTOPS_EVIDENCE_BUNDLES"}'

security-lakehouse connectors configure \
  --lake build/lakehouse \
  --connector-id snowflake-evidence-lake \
  --state enabled \
  --credentials-json '{"account":"fixture","user":"trustops_reader","credential_ref":"fixture-sso"}' \
  --options-json '{"warehouse":"TRUSTOPS_READ_WH","database":"TRUSTOPS_SECURITY_LAKE","schema":"EVIDENCE","audit_events":"TRUSTOPS_AUDIT_EVENTS","control_posture":"TRUSTOPS_CONTROL_POSTURE","asset_risk":"TRUSTOPS_ASSET_RISK","evidence_bundles":"TRUSTOPS_EVIDENCE_BUNDLES"}'

security-lakehouse connectors sync \
  --lake build/lakehouse \
  --connector-id snowflake-evidence-lake \
  --fixture-dir tests/fixtures/snowflake
```

ClickHouse is the high-velocity telemetry lake reader. The fixture path mirrors
`security.normalized_events` from `deploy/clickhouse/schema.sql` and uses
append-mode ingestion with a high-water cursor:

```bash
security-lakehouse connectors probe \
  --lake build/lakehouse \
  --connector-id clickhouse-telemetry-lake \
  --credentials-json '{"host":"https://cluster.example.clickhouse.cloud:8443","user":"trustops_reader","credential_ref":"TRUSTOPS_CLICKHOUSE_TOKEN"}' \
  --options-json '{"database":"security","table":"normalized_events"}'

security-lakehouse connectors configure \
  --lake build/lakehouse \
  --connector-id clickhouse-telemetry-lake \
  --state enabled \
  --credentials-json '{"host":"https://cluster.example.clickhouse.cloud:8443","user":"trustops_reader","credential_ref":"TRUSTOPS_CLICKHOUSE_TOKEN"}' \
  --options-json '{"database":"security","table":"normalized_events"}'

security-lakehouse connectors sync \
  --lake build/lakehouse \
  --connector-id clickhouse-telemetry-lake \
  --fixture-dir tests/fixtures/clickhouse-telemetry-lake
```

For live ClickHouse collection, point the connector at your cluster HTTP endpoint
and mount the read-only token via `TRUSTOPS_CLICKHOUSE_TOKEN` (or the
`credential_ref` you configured). TrustOps only issues `SELECT` reads against
the discovered table, keyset-paginated on the composite `(event_time, event_id)`
cursor with `LIMIT` so a large table streams in bounded pages instead of one
unbounded response; rows sharing an `event_time` across a page boundary are never
dropped, and the append-mode merge dedups by `event_id` as a second safety net.

### Alert- and event-export pagination (SIEM, runtime-gateway)

The `siem-alerts` and `runtime-gateway` readers pull an incremental window with a
watermark cursor (`?since=`) and follow server-side pagination within that window:
when a response is a JSON object carrying a `next_cursor` string, TrustOps requests
the next page with `?cursor=<token>` and repeats until `next_cursor` is absent. An
export that returns a bare JSON array (or an object without `next_cursor`) is read
as a single page, so a non-paginating endpoint still works unchanged.

For live Snowflake collection, install the cloud connector extra and use the
fixed POC objects from [`docs/LIVE_CLOUD_POC.md`](LIVE_CLOUD_POC.md):
`TRUSTOPS_SECURITY_LAKE.EVIDENCE`, `TRUSTOPS_READ_WH`, and `TRUSTOPS_READER`.
For a human POC, use browser SSO. This is not the scheduled-ingestion path.
TrustOps only issues `SELECT * FROM <view>` reads:

```bash
uv pip install -e ".[cloud]"

SNOWFLAKE_ACCOUNT="$SNOWFLAKE_ACCOUNT" \
SNOWFLAKE_USER="$SNOWFLAKE_USER" \
SNOWFLAKE_AUTHENTICATOR=externalbrowser \
SNOWFLAKE_ROLE=TRUSTOPS_READER \
SNOWFLAKE_WAREHOUSE=TRUSTOPS_READ_WH \
SNOWFLAKE_DATABASE=TRUSTOPS_SECURITY_LAKE \
SNOWFLAKE_SCHEMA=EVIDENCE \
security-lakehouse connectors sync \
  --lake build/lakehouse \
  --connector-id snowflake-evidence-lake
```

Headless jobs should use a non-human service user such as
`TRUSTOPS_INGEST_SVC`, with only `TRUSTOPS_READER` and warehouse `USAGE`.
Snowflake key-pair auth uses a mounted private-key file path, not raw key
contents in connector config:

```bash
security-lakehouse connectors probe \
  --lake build/lakehouse \
  --connector-id snowflake-evidence-lake \
  --credentials-json '{"account":"'"$SNOWFLAKE_ACCOUNT"'","user":"TRUSTOPS_INGEST_SVC","private_key_ref":"SNOWFLAKE_PRIVATE_KEY_FILE"}' \
  --options-json '{"warehouse":"TRUSTOPS_READ_WH","database":"TRUSTOPS_SECURITY_LAKE","schema":"EVIDENCE","role":"TRUSTOPS_READER","audit_events":"TRUSTOPS_AUDIT_EVENTS","control_posture":"TRUSTOPS_CONTROL_POSTURE","asset_risk":"TRUSTOPS_ASSET_RISK","evidence_bundles":"TRUSTOPS_EVIDENCE_BUNDLES"}'

SNOWFLAKE_ACCOUNT="$SNOWFLAKE_ACCOUNT" \
SNOWFLAKE_USER=TRUSTOPS_INGEST_SVC \
SNOWFLAKE_AUTHENTICATOR=SNOWFLAKE_JWT \
SNOWFLAKE_PRIVATE_KEY_FILE="$SNOWFLAKE_PRIVATE_KEY_FILE" \
SNOWFLAKE_ROLE=TRUSTOPS_READER \
SNOWFLAKE_WAREHOUSE=TRUSTOPS_READ_WH \
SNOWFLAKE_DATABASE=TRUSTOPS_SECURITY_LAKE \
SNOWFLAKE_SCHEMA=EVIDENCE \
security-lakehouse connectors sync \
  --lake build/lakehouse \
  --connector-id snowflake-evidence-lake
```

OAuth is also supported when the customer's runtime has a governed token broker:
set `SNOWFLAKE_AUTHENTICATOR=oauth` and inject `SNOWFLAKE_OAUTH_TOKEN` from the
secret manager at process start. The raw value is not written into the lake.

Object storage evidence uses read-only LIST against an S3 prefix and syncs in
**snapshot** mode so removed objects disappear from the lake on the next pull:

```bash
security-lakehouse connectors probe \
  --lake build/lakehouse \
  --connector-id object-storage-evidence \
  --credentials-json '{"role_arn":"arn:aws:iam::123456789012:role/TrustOpsEvidenceRead"}' \
  --options-json '{"bucket":"trustops-evidence","prefix":"bundles/"}'

security-lakehouse connectors configure \
  --lake build/lakehouse \
  --connector-id object-storage-evidence \
  --state enabled \
  --credentials-json '{"role_arn":"arn:aws:iam::123456789012:role/TrustOpsEvidenceRead"}' \
  --options-json '{"bucket":"trustops-evidence","prefix":"bundles/"}'

security-lakehouse connectors sync \
  --lake build/lakehouse \
  --connector-id object-storage-evidence \
  --fixture-dir tests/fixtures/object-storage-evidence
```

By default the runner rebuilds bronze, silver, gold, marts, and current posture
from the managed raw connector file. Use `--no-materialize` when you only want
to collect raw evidence. Every sync attempt is recorded in
`gold/connector_runs.jsonl`.

## Scheduled Sync

Manual sync proves the connector. Scheduled sync makes the connector part of
continuous posture.

Persist scheduler options on the connector configuration:

```bash
security-lakehouse connectors probe \
  --lake build/lakehouse \
  --connector-id github-security \
  --credentials-json '{"credential_ref":"TRUSTOPS_GITHUB_APP_INSTALLATION_TOKEN"}' \
  --options-json '{"repo":"OWNER/REPO"}'

security-lakehouse connectors configure \
  --lake build/lakehouse \
  --connector-id github-security \
  --state enabled \
  --credentials-json '{"credential_ref":"TRUSTOPS_GITHUB_APP_INSTALLATION_TOKEN"}' \
  --options-json '{"repo":"OWNER/REPO"}' \
  --sync-schedule "every 15m" \
  --repo OWNER/REPO
```

Run the scheduler from cron, Kubernetes `CronJob`, or the local daemon:

```bash
security-lakehouse scheduler tick --lake build/lakehouse
security-lakehouse scheduler run --lake build/lakehouse --tick-seconds 60
```

Supported schedule expressions are intentionally small and portable:
`@hourly`, `@daily`, `every Nm`, and `every Nh`. The scheduler records last
fire time in `gold/scheduler_state.jsonl`, writes sync history to
`gold/connector_runs.jsonl`, and uses the same connector runner as
`connectors sync`; it does not use a separate evidence path.

Repository evidence has two concrete collection paths:

```bash
security-lakehouse repo audit https://github.com/OWNER/REPO --out build/repo-audit.jsonl
TRUSTOPS_GITHUB_APP_INSTALLATION_TOKEN=... security-lakehouse repo governance-sync OWNER/REPO --out build/repo-governance.jsonl
```

The public audit path requires no credentials. The governance sync path uses a
GitHub App installation token or fixture bundle for private branch rules,
collaborators, teams, workflow permissions, and security-setting summaries.

The validator rejects:

- missing collection mode, access boundary, route, permissions, or freshness SLO
- existing-lake connectors that are not read-only
- direct API connectors that are not scoped-token based
- managed evidence mode without a dedicated schema/boundary
- secret-like field names or token-shaped values in the catalog
- broad permission words such as admin, delete, drop, modify, owner, or root

## Ingestion strategy (velocity + cost)

A compliance data layer that claims _real-time control health_ must justify
**how** each source is ingested, because streaming is not free. Every connector
declares three attributes that drive an auditable ingestion decision (encoded in
`src/security_lakehouse/ingestion/strategy.py`, not prose):

- `velocity`: `high_event_stream` · `medium_api` · `low_current_state`
- `native_connector`: whether a managed/native ingestion connector exists for the source
- `data_shape`: `event_log` · `current_state`

| Velocity            | Native? | Method                                       | Why                                                                                                                                                                                                       |
| ------------------- | ------- | -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `high_event_stream` | any     | **Snowpipe Streaming**                       | Seconds-fresh, serverless, no warehouse COPY; ~50% cheaper than file Snowpipe at high throughput (unified ~0.0037 credits/GB). INSERT-only — upserts handled downstream via Streams/Tasks/Dynamic Tables. |
| `medium_api`        | true    | **Managed/native connector** (e.g. Openflow) | Managed runtime, less code, vendor-managed auth, built-in observability.                                                                                                                                  |
| `medium_api`        | false   | **Committed custom pull**                    | No native connector: watermark + cursor pagination + 429 backoff + idempotent merge.                                                                                                                      |
| `low_current_state` | any     | **Scheduled pull** (hourly/daily)            | Slow churn; streaming would add producer cost + ops for zero freshness benefit the control needs.                                                                                                         |

**Cost discipline:** streaming bills per client-runtime-hour + per-GB and you own
the producer. The strategy makes `high_event_stream` the _only_ path to streaming,
so it is chosen only when a control's `freshness_slo` actually requires sub-minute
data — never claimed where a native connector does not exist.

Inspect the resolved plan per source (a live demo command):

```bash
security-lakehouse ingestion plan        # table: velocity → method → SLO + cost note
security-lakehouse ingestion plan --json  # machine-readable
```

## Okta: two velocities, not one

A common misread is "Okta is high-volume, so stream it." Okta actually exposes
**two sources at very different velocities**, and most access _controls_ read the
slow one:

| Source            | data_shape      | velocity            | freshness | ingestion                                                              | feeds                                              |
| ----------------- | --------------- | ------------------- | --------- | ---------------------------------------------------------------------- | -------------------------------------------------- |
| `okta-identity`   | `current_state` | `low_current_state` | 1h        | scheduled pull                                                         | MFA-coverage, orphaned/terminated-account controls |
| `okta-system-log` | `event_log`     | `medium_api`        | 15m       | **implemented** — incremental pull with watermark cursor + 429 backoff | failed-login / auth-anomaly controls (e.g. AC-7)   |

The current-state source (users, factors, policies) changes slowly, so an hourly
scheduled pull is correct and cheapest. The System Log is event-shaped and needs
~15-minute freshness for failed-login controls; it is pulled incrementally with a
high-water cursor (`gold/watermarks.jsonl`) rather than streamed, because the
Okta System Log is a polled API. Modeling them separately keeps each control on
the right freshness/cost path instead of over-provisioning the whole connector to
the strictest SLO.

## Google Workspace: two credential shapes

`google-workspace-identity` accepts either an already-minted access token or the
OAuth material to mint tokens itself. Pick one:

| Shape               | Credentials                                             | When                                                                     |
| ------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------ |
| Static access token | `credential_ref`                                        | Your secret manager already rotates a short-lived Directory access token |
| Unattended refresh  | `refresh_token_ref` + `client_id` + `client_secret_ref` | Scheduled sync with nothing external minting tokens                      |

Both need `customer_id`. The `*_ref` fields name environment variables, never raw
secrets; a `<NAME>_FILE` variant is preferred over the inline value when both are
present. With the refresh shape, TrustOps exchanges the refresh token at
`oauth2.googleapis.com/token` on first use, near expiry (300s skew), or once on a
401, and the resolved access token stays in memory only.

```bash
security-lakehouse connectors probe \
  --lake build/lakehouse \
  --connector-id google-workspace-identity \
  --credentials-json '{"customer_id":"C01234567","refresh_token_ref":"GOOGLE_WORKSPACE_REFRESH_TOKEN","client_id":"123-abc.apps.googleusercontent.com","client_secret_ref":"GOOGLE_WORKSPACE_OAUTH_CLIENT_SECRET"}'
```

Supplying part of the refresh triple is rejected at probe and enable time with the
specific missing fields, because a partial triple silently falls back to the
static-token path at sync time.

## Microsoft Intune: device posture

`intune-devices` reads `GET /v1.0/deviceManagement/managedDevices` from Microsoft
Graph and emits two current-state events per managed device:

| Event                      | Pass when                                           | Controls                                               |
| -------------------------- | --------------------------------------------------- | ------------------------------------------------------ |
| `intune.device.encryption` | `isEncrypted` is true                               | FEDRAMP-AC-19.5, CMMC-3.1.19, ISO27001-A.8.1           |
| `intune.device.compliance` | `complianceState` is `compliant` and not jailbroken | FEDRAMP-AC-19, CMMC-3.1.18, SOC2-CC6.8, ISO27001-A.8.1 |

`noncompliant`, `conflict`, `error`, or a jailbroken/rooted device is a high-severity
open finding; `inGracePeriod` is low; `unknown` and `configManager` are medium,
because Intune has no verdict to rely on.

**Identity.** The same `DefaultAzureCredential` model as `azure-posture`: an Entra
app registration (workload identity federation or managed identity) with the Graph
**application** permission `DeviceManagementManagedDevices.Read.All` and admin
consent. The only stored field is `tenant_id` (`AZURE_TENANT_ID` overrides it); no
client secret is stored in TrustOps. The tenant needs an active Intune license.

**Data minimization.** The list call uses `$select` for posture fields only.
IMEI, serial number, MAC addresses, phone number, user display name, and admin
notes are never requested. `userPrincipalName` is kept as the join key to
identity-provider users. Pagination follows `@odata.nextLink` only while it stays on
`https://graph.microsoft.com`, so the bearer token is never sent elsewhere.

## BambooHR: employment records

`bamboohr-personnel` reads BambooHR's `employee` dataset
(`POST https://{company_domain}.bamboohr.com/api/v2/datasets/employee/data`,
paged 500 rows at a time) and emits one current-state
`hris.personnel.employment` event per employee. The event shape is vendor-neutral
(`security_lakehouse/hris.py`), so later HRIS connectors emit the same record.

| Requested field            | Lands as            |
| -------------------------- | ------------------- |
| `eeid`                     | `employee_id`       |
| `employeeNumber`           | `employee_number`   |
| `email` (work email)       | `work_email`        |
| `employmentStatus`         | `employment_status` |
| `hireDate`                 | `hire_date`         |
| `terminationDate`          | `termination_date`  |
| `jobInformationDepartment` | `department`        |
| `supervisorEid`            | `manager_id`        |

`is_terminated` is true when the termination date is on or before the collection
date. Events feed FEDRAMP-PS-4, FEDRAMP-PS-5, ISO27001-A.6.5, CMMC-3.9.2, and
HIPAA-164.308(a)(3) as personnel-lifecycle evidence. Whether access was actually
removed is answered by the [offboarding check](#offboarding-check-hr-terminations--idp-accounts).

**PII boundary.** Only the fields above are requested. Names, dates of birth,
government IDs, compensation, addresses, and personal contact details are never
requested. Personnel attributes stay in raw/bronze (silver and gold carry ids and
status only) and are marked `data_sensitivity: confidential`, so auditor and
public-share roles see them redacted.

**Credentials.** BambooHR API keys inherit the permissions of the user who created
them. Create a dedicated user whose access level can view only these fields, and
store its key as a secret reference (`credential_ref`, default
`BAMBOOHR_API_KEY`; a `<NAME>_FILE` variant is preferred). `company_domain` must be
the bare subdomain (`acme` for `acme.bamboohr.com`); anything else is rejected, so
the authenticated request can never be pointed at another host.

## Rippling: employment records

`rippling-personnel` reads `GET https://rest.ripplingapis.com/workers/` (Rippling
REST API, scope `workers.read`, cursor pages of 100 via `next_link`) and emits the
same `hris.personnel.employment` event as BambooHR: `id` → `employee_id`, `number`,
`work_email`, `status`, `start_date` → `hire_date`, `end_date` →
`termination_date`, `department_id`, and `manager_id`.

The workers endpoint cannot select fields, so its response can include date of
birth, gender, compensation ids, and personal email. The connector copies only
the fields above and discards the rest before anything is written. `next_link` is
followed only while it stays on `https://rest.ripplingapis.com`. Store the token as
a secret reference (`credential_ref`, default `RIPPLING_API_TOKEN`).

## Workday: employment records (RaaS)

Workday's public Staffing REST worker resource has no termination date or work
email, so `workday-personnel` reads a tenant-defined custom report published as a
web service (RaaS). Build an advanced report on workers (include terminated
workers) with exactly these column aliases:

| Column             | Content                                 |
| ------------------ | --------------------------------------- |
| `Employee_ID`      | Employee or contingent worker ID        |
| `Work_Email`       | Primary work email                      |
| `Worker_Status`    | Active / terminated status              |
| `Hire_Date`        | Hire date (`YYYY-MM-DD`)                |
| `Termination_Date` | Termination date, empty if none         |
| `Department`       | Supervisory organization or cost center |
| `Manager_ID`       | Manager's employee ID                   |

Enable it as a web service, share it with a read-only integration system user,
and configure `report_url` (the report's `…?format=json` URL), `username`, and
the ISU password as a secret reference (`credential_ref`, default
`WORKDAY_ISU_PASSWORD`). The URL must be https on a Workday domain
(`*.workday.com`, `*.myworkday.com`, `*.myworkdaygov.com`), request
`format=json`, and carry no embedded credentials. Rows are read from the
`Report_Entry` list; other columns are ignored and never stored. The same
PII boundary and `data_sensitivity: confidential` marking apply to all three HRIS
connectors, and all three feed the offboarding check below.

## Databricks evidence lake (preview)

`databricks-evidence-lake` is an existing-lake reader. It runs
`SELECT * FROM` each of the four TrustOps evidence views in a Unity Catalog
schema through the SQL Statement Execution API (`POST /api/2.0/sql/statements`,
`INLINE` + `JSON_ARRAY`, polling while `PENDING`/`RUNNING`, following
`next_chunk_internal_link`). No Databricks SDK or driver is installed.

Setup:

1. Run [`deploy/databricks/bootstrap_poc.sql`](../deploy/databricks/bootstrap_poc.sql)
   as a user who can create a catalog and read `system.access.audit`, replacing
   `<trustops-sp-application-id>` with a service principal's application id.
2. Grant that service principal `CAN USE` on one SQL warehouse.
3. Create an OAuth secret for the service principal and store it as a secret
   reference (`client_secret_ref`, default `DATABRICKS_CLIENT_SECRET`).
4. Configure `host`, `warehouse_id`, `catalog`, `schema`, and `client_id`, then
   probe and enable.

TrustOps mints a one-hour token at `https://<host>/oidc/v1/token`
(`client_credentials`, `scope=all-apis`) per sync and keeps it in memory. The
host must be a Databricks workspace domain (`*.cloud.databricks.com`,
`*.azuredatabricks.net`, `*.gcp.databricks.com`); result chunk links may not
leave it; catalog, schema, and view names are strict identifiers quoted with
backticks. The bootstrap views keep the latest 10,000 audit events so a read
stays under the 25 MiB inline result limit. This connector has not yet been
verified against a live workspace.

## Jamf Pro: macOS and iOS device posture (preview)

`jamf-devices` reads the Jamf Pro API (11.32 reference) — `GET /api/v4/computers-inventory`,
`GET /api/v2/mobile-devices/detail` (both paged 100 at a time), and
`GET /api/v1/managed-software-updates/available-updates` — and emits current-state
events per managed Mac and iPhone/iPad:

| Event                     | Pass when                                                                                 | Controls                                                                                 |
| ------------------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `jamf.device.encryption`  | FileVault boot volume encrypted (Mac) or `dataProtected` (iOS)                            | FEDRAMP-AC-19.5, CMMC-3.1.19, ISO27001-A.8.1                                             |
| `jamf.device.management`  | Managed, not jailbroken, and checked in within 30 days                                    | FEDRAMP-AC-19, CMMC-3.1.18, SOC2-CC6.8, ISO27001-A.8.1, FEDRAMP-CM-8                     |
| `jamf.device.os_patch`    | OS version is the newest Apple offers for that major version                              | FEDRAMP-SI-2, CMMC-3.14.1, ISO27001-A.8.8, SOC2-CC7.1, CIS-CONTROLS-7, NIST-CSF-PR.PS-02 |
| `jamf.device.screen_lock` | Passcode present and compliant (iOS), or the configured extension attribute is true (Mac) | FEDRAMP-AC-11, CMMC-3.1.10, ISO27001-A.8.1                                               |
| `jamf.device.firewall`    | macOS application firewall enabled                                                        | FEDRAMP-CM-6, CMMC-3.4.2, CIS-CONTROLS-4, ISO27001-A.8.1                                 |

Encryption and management use the same controls as `intune-devices`, so either MDM
satisfies them. An unencrypted disk, an unmanaged or jailbroken device, a missing
passcode, or a macOS major version Apple no longer offers updates for is high; an
available update, a stale check-in, a disabled firewall, or an unenforced screen lock
is medium; encryption in progress is low. Signals Jamf does not report are not
emitted rather than guessed: Jamf inventory has no macOS screen-lock field, so Macs
are evaluated only when you name a computer extension attribute
(`screen_lock_attribute`) that reports it; Apple TV and Apple Watch get only the
management event; and if the API client cannot read the available-updates feed (403
or 404) no patch verdict is emitted.

**Least privilege.** In Jamf Pro, **Settings > System > API roles and clients**:

1. Create an API role with only **Read Computers** and **Read Mobile Devices**.
2. Create an API client with that role, enable it, and generate a client secret.
3. Store the secret in your secret store and configure `base_url`
   (`https://yourcompany.jamfcloud.com`), `client_id`, and `client_secret_ref`
   (default `JAMF_CLIENT_SECRET`).

TrustOps exchanges the client credentials at `POST {base_url}/api/v1/oauth/token`
for a short-lived bearer token held in memory only, re-mints it once on a 401, and
fails closed after that. No Jamf user account or password is used.

**Data minimization.** Only the GENERAL, DISK_ENCRYPTION, OPERATING_SYSTEM, SECURITY,
and USER_AND_LOCATION sections are requested (EXTENSION_ATTRIBUTES only when a
screen-lock attribute is configured). From them TrustOps keeps device ID and name,
platform, OS version, encryption, firewall and passcode state, managed and check-in
state, and the assigned user's email (the join key to identity-provider users). IP
addresses, serial numbers, usernames, real names, phone numbers, recovery keys, and
locations are dropped before anything is stored. Every request goes only to the
configured `base_url` through the public-egress guard with 429/5xx backoff.

## CrowdStrike Falcon: sensor coverage and prevention (preview)

`crowdstrike-falcon` reads the Falcon API of one CrowdStrike cloud and emits
current-state endpoint evidence:

| Event                                | Pass when                                                                  | Controls                                                                                  |
| ------------------------------------ | -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `crowdstrike.host.sensor`            | The sensor reported within 7 days and is not in reduced functionality mode | SOC2-CC6.8, FEDRAMP-SI-3, CMMC-3.14.2, ISO27001-A.8.7, CIS-CONTROLS-10, NIST-CSF-DE.CM-09 |
| `crowdstrike.host.prevention_policy` | An enabled prevention policy is assigned and applied                       | SOC2-CC6.8, FEDRAMP-SI-3, CMMC-3.14.2, ISO27001-A.8.7                                     |
| `crowdstrike.detections.summary`     | No unresolved critical, high, or medium alerts from the last 30 days       | SOC2-CC7.2, FEDRAMP-SI-4, CMMC-3.14.6, ISO27001-A.8.16, NIST-CSF-DE.CM-09                 |

Reduced functionality mode, a missing, disabled, unapplied, or unknown prevention
policy, and an unresolved critical or high alert are high-severity open findings. A
sensor that has not reported in 7 days, or never reported, is medium.

**Least privilege.** On the Falcon console's API clients and keys page, create an API client with only **Hosts: Read**, **Prevention policies: Read**,
and **Alerts: Read**. Store its secret and configure `cloud` (`us-1`, `us-2`, `eu-1`,
`us-gov-1`, `us-gov-2`), `client_id`, and `client_secret_ref` (default
`CROWDSTRIKE_CLIENT_SECRET`). TrustOps exchanges the client credentials at
`https://<cloud API host>/oauth2/token` for a short-lived token held in memory only
and re-mints it once on a 401.

**Calls.** `GET /devices/queries/devices-scroll/v1`, then
`POST /devices/entities/devices/v2` (5,000 IDs per call);
`GET /policy/combined/prevention/v1`; and `POST /alerts/combined/alerts/v1` filtered to
`status:!'closed'` within a 30-day window. All requests go to the selected cloud's API
host through the public-egress guard; a 429 waits for `X-RateLimit-RetryAfter` (or
`Retry-After`).

**Data minimization.** Only host ID, hostname, platform, OS and sensor version, first
and last seen, containment status, reduced-functionality flag, and prevention policy
assignment are kept. MAC and IP addresses, serial numbers, user names, and tags are
dropped before storage. From alerts, only ID, status, severity, and creation time are
used, and only to compute the summary counts.

## Kubernetes: cluster configuration baseline (preview)

`kubernetes-cluster` reads cluster configuration with `list` calls only, using the
official Kubernetes Python client
(`pip install 'trustops-security-data-lake[kubernetes]'`), and emits current-state
events:

| Event                                   | Open when                                                                                               | Controls                                                                                              |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `kubernetes.rbac.cluster_admin_binding` | A (Cluster)RoleBinding grants `cluster-admin` to a non-`system:` subject (CIS 5.1.1)                    | FEDRAMP-AC-6, FEDRAMP-AC-6.5, CMMC-3.1.5, SOC2-CC6.3, ISO27001-A.8.2, NIST-CSF-PR.AA-05               |
| `kubernetes.workload.pod_security`      | Privileged, hostPath, host namespaces (high); root or privilege escalation allowed (medium) (CIS 5.2.x) | FEDRAMP-CM-6, FEDRAMP-CM-7, CMMC-3.4.2, CMMC-3.4.6, ISO27001-A.8.9, CIS-CONTROLS-4, NIST-CSF-PR.PS-01 |
| `kubernetes.namespace.network_policy`   | A namespace has no NetworkPolicy (CIS 5.3.2)                                                            | FEDRAMP-SC-7, CMMC-3.13.1, ISO27001-A.8.22                                                            |
| `kubernetes.workload.image_registry`    | An image is outside `allowed_registries` (medium) or uses `latest`/no tag without a digest (low)        | FEDRAMP-CM-7.5, NIST-CSF-PR.PS-05, CIS-CONTROLS-2                                                     |
| `kubernetes.workload.secret_env`        | Secrets are injected as environment variables (CIS 5.4.1)                                               | FEDRAMP-SC-28, CMMC-3.13.16, NIST-CSF-PR.DS-01                                                        |
| `kubernetes.cluster.audit_logging`      | The kube-apiserver lacks `--audit-policy-file` plus a log or webhook sink (CIS 1.2.16, 3.2.1)           | FEDRAMP-AU-2, FEDRAMP-AU-12, CMMC-3.3.1, ISO27001-A.8.15, NIST-CSF-PR.PS-04, CIS-CONTROLS-8           |

CIS references are to the CIS Kubernetes Benchmark v1.10. Workloads are evaluated on
their controller's pod template (Deployment, DaemonSet, StatefulSet, CronJob, and
ownerless ReplicaSets, Jobs, and Pods), so a pod is never counted twice. Without
`allowed_registries`, image evidence is recorded as `observed` inventory, never as a
pass. The built-in `cluster-admin` binding to `system:masters` is recorded as
`observed`. System namespaces are not exempted: privileged CNI or CSI DaemonSets in
`kube-system` show as findings, tagged `system_namespace`.

**Audit logging on managed clusters.** EKS, GKE, and AKS do not expose the API server
to the cluster, so no audit-logging event is emitted there; evidence audit logging
through the cloud posture connector instead. Self-managed clusters (kubeadm and
similar) expose the apiserver static pod and are evaluated.

**Least privilege.** Use a kubeconfig for a dedicated identity (optionally a named
`context`; `kubeconfig_ref` names the env var holding its path, default `KUBECONFIG`)
or the in-cluster service account when TrustOps runs inside the cluster. Bind it to
this get/list-only ClusterRole — never `view`, `edit`, or `cluster-admin`, and no
access to Secrets:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: trustops-config-reader
rules:
  - apiGroups: [""]
    resources: ["namespaces", "pods"]
    verbs: ["get", "list"]
  - apiGroups: ["apps"]
    resources: ["deployments", "daemonsets", "statefulsets", "replicasets"]
    verbs: ["get", "list"]
  - apiGroups: ["batch"]
    resources: ["cronjobs", "jobs"]
    verbs: ["get", "list"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterrolebindings", "rolebindings"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: trustops-config-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: trustops-config-reader
subjects:
  - kind: ServiceAccount
    name: trustops
    namespace: trustops
```

**Egress.** The client talks directly to the operator-configured API server. Cluster
endpoints are usually private addresses, so the public-address egress guard used for
SaaS APIs does not apply here. Lists page with `limit`/`continue` and retry 429/5xx
honoring `Retry-After`.

**Data minimization.** Secret objects are never listed. Environment variable values,
container commands and args, labels, and annotations are never stored; only the names
of Secret-backed variables, image references, and binding subjects are kept.

## KnowBe4: security awareness training (preview)

`knowbe4-training` reads the KnowBe4 Reporting API
(`https://{region}.api.knowbe4.com`, region `us`, `eu`, `ca`, `uk`, or `de`):
`GET /v1/users?status=active`, `GET /v1/training/enrollments?exclude_archived_users=true`,
and `GET /v1/phishing/security_tests`, paged 500 rows at a time.

| Event                      | Pass when                                                             | Controls                                                                                                                                |
| -------------------------- | --------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `knowbe4.user.training`    | Every enrollment is `Completed` or `Passed`                           | FEDRAMP-AT-2, FEDRAMP-AT-4, CMMC-3.2.1, CMMC-3.2.2, ISO27001-A.6.3, NIST-CSF-PR.AT-01, CIS-CONTROLS-14, SOC2-CC1.4, HIPAA-164.308(a)(5) |
| `knowbe4.phishing.summary` | Delivery-weighted phish-prone % of tests in the last 90 days is < 20% | FEDRAMP-AT-2, CMMC-3.2.1, ISO27001-A.6.3, NIST-CSF-PR.AT-01, CIS-CONTROLS-14                                                            |

Any `Past Due` enrollment is an open medium finding (`training_overdue`); only
`Not Started`/`In Progress` is open low (`training_incomplete`); an active user with no
enrollment is open medium (`not_enrolled`). The enrollment schema has no due date, so
`Past Due` is KnowBe4's own verdict. No phishing test in the last 90 days is
`observed`, never a pass. The 20% threshold is a TrustOps default, not a KnowBe4
benchmark.

**Least privilege.** A Reporting API key from the KnowBe4 Reporting API console
(Platinum, Diamond, SAT Foundation, or SAT Advanced subscription). The key is read-only
reporting for the whole account — KnowBe4 offers no finer scope — and is not the User
Event API key. Store it as a secret and reference it with `credential_ref` (default
`KNOWBE4_API_TOKEN`); only the region is stored in TrustOps. Anonymized consoles return
no per-user data.

**Rate limits.** KnowBe4 allows 4 requests/second, a 50/minute burst, and 2,000 plus
licensed users per day. The client paces requests at least 1.25 s apart and retries
429/5xx honoring `Retry-After`.

**Data minimization.** Only user ID, primary email (the join key to identity-provider
and HRIS records), employee number, enrollment status counts, last completion date,
and phish-prone percentage are kept. Names, job titles, phone numbers, locations,
divisions, manager details, aliases, and custom fields are dropped before anything is
stored. The key is only ever sent to the configured regional host.

## Existing lakes: mappings, Iceberg/Parquet, BigQuery (preview)

The Snowflake, Databricks, and ClickHouse readers can read existing tables
through a lake mapping (`options.mapping` / `options.mappings`) instead of the
TrustOps views. `iceberg-parquet-lake` reads Iceberg tables through AWS Glue
(including Amazon Security Lake, with OCSF presets by default) or an Iceberg REST
catalog, and Parquet on S3 or an allowed local root. `bigquery-evidence-lake` reads
BigQuery tables with Application Default Credentials. The spec, the OCSF presets,
`lake map --dry-run`, and per-backend least-privilege setup are in
[BRING_YOUR_OWN_LAKE.md](BRING_YOUR_OWN_LAKE.md).

## Offboarding check: HR terminations ↔ IdP accounts

After any sync that writes HR employment rows (`hris.personnel.employment`, from
any HRIS connector) or identity-provider user rows (`okta-identity`,
`google-workspace-identity`), TrustOps rebuilds one derived row per terminated
employee. It joins HR records to IdP accounts on the lower-cased work email and
writes the result as a snapshot under the derived id `hris-idp-offboarding`
(source `trustops-correlation`), so a fixed account clears on the next sync.

| Outcome                    | Meaning                                                        | Status     |
| -------------------------- | -------------------------------------------------------------- | ---------- |
| `active_after_termination` | An account can still sign in after the grace period            | open, high |
| `within_grace_period`      | Still active, but inside the grace period                      | observed   |
| `deprovisioned`            | Every matched account is disabled                              | pass       |
| `no_idp_account_matched`   | No IdP account shares the work email (never counted as a pass) | observed   |

Rows map to SOC2-CC6.2, FEDRAMP-PS-4, FEDRAMP-AC-2.3, ISO27001-A.5.18,
ISO27001-A.6.5, and CMMC-3.9.2, each of which fails on an open violation. Nothing
is produced until both HR and IdP evidence exist, and future-dated terminations are
ignored. The grace period defaults to 1 day; set
`TRUSTOPS_OFFBOARDING_GRACE_DAYS` (0–365) to change it. Attributes (including the
work email and matched account ids) are marked `data_sensitivity: confidential`.
The derive step runs under the same raw-file lock as connector writes, so
concurrent HR and IdP syncs cannot each derive from a partial view.
