# Human And Agent API

The API is the shared control surface for the TrustOps console, coding agents,
CI jobs, MCP tools, and reviewer workflows. Route names describe assessment
concepts, not storage implementation details.

<p align="center">
  <img src="../images/trustops-agent-api-flow.svg" alt="TrustOps human and agent API flow with callers, versioned API boundary, RBAC, audit, and composable skills" width="100%">
</p>

Humans and agents use the same facts:

| Caller           | First action                                    | Allowed actions                                                       | Audit boundary                                             |
| ---------------- | ----------------------------------------------- | --------------------------------------------------------------------- | ---------------------------------------------------------- |
| Human console    | Load current posture and work queues            | Triage, request evidence, create snapshots, run guarded workflows     | Session or API key identity, tenant, role, route, decision |
| Coding/GRC agent | Read posture, then control tests and violations | Explain gaps, propose owner actions, create snapshots only when asked | API key identity, scoped role, correlation ID              |
| CI/release gate  | Read posture-as-of or current posture           | Fail or warn on policy threshold; optionally create release snapshot  | API key identity, route, decision, status                  |
| MCP client       | Call the same v1 resources as tools             | Read/write tools only where the role allows it                        | Same RBAC and audit event model                            |

Use `/api/v1/*` for external automation. Versioned responses always use:

```json
{
  "data": [],
  "meta": {
    "api_version": "v1",
    "resource": "control-tests",
    "count": 4,
    "returned": 4,
    "limit": 100,
    "offset": 0,
    "sort": null,
    "filters": {}
  },
  "errors": []
}
```

List routes support:

- `limit`: 1-1000, default 100
- `offset`: zero-based row offset
- `sort`: field name, or `-field` for descending
- field filters: exact scalar match, list membership match, comma-separated OR
  values

## End-To-End Flow

```mermaid
sequenceDiagram
  autonumber
  participant Source as Evidence source
  participant Ingest as Ingestion skill
  participant Lake as TrustOps lake
  participant Eval as Evaluation skill
  participant API as /api/v1
  participant Human as Human reviewer
  participant Agent as Coding/GRC agent

  Source->>Ingest: scoped read-only evidence
  Ingest->>Lake: bronze replay + raw_sha256
  Ingest->>Lake: silver normalized fact
  Eval->>Lake: controls-as-code over fresh evidence
  Eval->>API: gold posture, tests, violations
  Human->>API: open failing control
  Agent->>API: read same control test and evidence refs
  Agent->>API: request snapshot when explicitly asked
  API->>Lake: append audit event + snapshot hash
```

The important rule: the workbench is not a special surface. Every significant
human action should have the same JSON contract an agent can call, and every
agent action should be rendered back to humans with the same audit trail.

## Routes

| Method | Path                                                             | Purpose                                                                                                                                   |
| ------ | ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `GET`  | `/api/v1/healthz`                                                | service health                                                                                                                            |
| `GET`  | `/api/v1/posture/current`                                        | continuously evaluated posture                                                                                                            |
| `GET`  | `/api/v1/posture/as-of`                                          | posture at a point in time                                                                                                                |
| `GET`  | `/api/v1/control-tests`                                          | control tests with owners, evidence requirements, confidence, and next action                                                             |
| `GET`  | `/api/v1/violations`                                             | open control and asset violations                                                                                                         |
| `GET`  | `/api/v1/controls`                                               | control workbench data                                                                                                                    |
| `GET`  | `/api/v1/evidence`                                               | normalized evidence facts, filterable by any top-level field                                                                              |
| `GET`  | `/api/v1/ccf/assessment`                                         | Published safeguard/asset results and reviewed requirement rollups, scoped to observed assets; inventory completeness is not established. |
| `GET`  | `/api/v1/evidence/freshness`                                     | evidence freshness rows with SLO status, age, reason, and next action                                                                     |
| `GET`  | `/api/v1/assets`                                                 | asset risk queue                                                                                                                          |
| `GET`  | `/api/v1/snapshots`                                              | list point-in-time assessment snapshots                                                                                                   |
| `POST` | `/api/v1/snapshots`                                              | create a point-in-time assessment snapshot                                                                                                |
| `GET`  | `/api/v1/agent-runs`                                             | persisted human/headless harness runs                                                                                                     |
| `POST` | `/api/v1/agent-runs`                                             | run and persist a deterministic, optional LangGraph-orchestrated, or optional model-assisted harness with data-readiness preflight        |
| `GET`  | `/api/v1/agent-runs/{run_id}`                                    | inspect one persisted harness run, including evaluation and proposed actions                                                              |
| `POST` | `/api/v1/agent-runs/{run_id}/decisions/{decision_index}/approve` | approve one stored proposal and execute its allowlisted TrustOps write idempotently                                                       |
| `GET`  | `/api/v1/audit-log`                                              | unified activity stream (`event_id`, `occurred_at`, category filters)                                                                     |
| `GET`  | `/api/v1/connectors`                                             | connector catalog + live sync health                                                                                                      |
| `GET`  | `/api/v1/connectors/{id}/runs`                                   | probe, discover, and sync run history                                                                                                     |
| `POST` | `/api/v1/connectors/{id}/sync`                                   | trigger read-only connector sync (idempotent raw upsert on `event_id`)                                                                    |
| `POST` | `/api/v1/connectors/{id}/discover`                               | list selectable scope without enabling collection (`connector_manage`)                                                                    |
| `POST` | `/api/v1/connectors/{id}/probe`                                  | validate credentials and read scope; writes fingerprint (`connector_manage`)                                                              |
| `POST` | `/api/v1/connectors/{id}/configure`                              | enable/disable connector after successful probe (`connector_manage`)                                                                      |
| `GET`  | `/api/v1/ingestion/status`                                       | continuous loop health: schedules, scale tier, connector freshness, last eval, `next_eval_at`, `eval_overdue`                             |
| `POST` | `/api/v1/ingestion/eval`                                         | run lake-wide materialize + evaluate (`connector_manage`)                                                                                 |
| `GET`  | `/api/v1/ingestion/eval/runs`                                    | recent lake evaluation runs (split ingest/eval schedules)                                                                                 |
| `POST` | `/api/v1/scheduler/tick`                                         | fire due connector syncs, lake eval, and cron workflows once (`connector_manage`)                                                         |
| `GET`  | `/api/v1/stream`                                                 | SSE continuous-eval stream (posture, freshness, audit-readiness on change)                                                                |
| `GET`  | `/api/v1/controls/{control_id}/remediation`                      | per-control remediation guidance from bundled catalog (`read`)                                                                            |
| `POST` | `/api/v1/insights/capture`                                       | append posture metric point for trends (`write`)                                                                                          |
| `GET`  | `/api/v1/platform/usage`                                         | hosted plan tier and usage vs limits (`admin`)                                                                                            |
| `GET`  | `/api/v1/snapshots/{snapshot_id}/export.pdf`                     | executive PDF export for a point-in-time snapshot (`read`)                                                                                |
| `GET`  | `/api/v1/oscal/component-definition`                             | NIST OSCAL component-definition JSON from the CCF safeguards + catalog                                                                    |
| `GET`  | `/api/v1/oscal/assessment-results`                               | NIST OSCAL assessment-results JSON from current (or `?snapshot_id=`) posture                                                              |

The unversioned `/api/*` routes remain for the bundled console and local
compatibility. Prefer **`/api/v1/*`** for agents and CI.

Use the `describe_api` MCP tool or `GET /api/v1` index for the full resource
catalog (50+ routes including insights, gov-compliance, vendor risk, and GRC).

**Agent skill bundles** (intent → routes → MCP): [AGENT_SKILLS.md](AGENT_SKILLS.md)

**Committed OpenAPI:** [openapi.v1.json](openapi.v1.json) — regenerate with `make openapi-export`

See [CONTINUOUS_INGESTION.md](../CONTINUOUS_INGESTION.md) for the production
operating model and [INGESTION_CONNECTORS_IDEMPOTENCY.md](../INGESTION_CONNECTORS_IDEMPOTENCY.md)
for connector registry, unique IDs, timestamps, and idempotency keys.

### Ingestion and scheduler pattern

```bash
# Health check before acting
curl -s -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8787/api/v1/ingestion/status | jq .

# Manual lake eval (same engine as split eval_schedule)
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8787/api/v1/ingestion/eval \
  -H 'content-type: application/json' \
  --data '{"actor":"ci"}' | jq .

# Production CronJob / orchestrator tick
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8787/api/v1/scheduler/tick \
  -H 'content-type: application/json' --data '{}' | jq .
```

MCP equivalents: `get_ingestion_status`, `list_eval_runs`, `run_lake_eval`,
`run_scheduler_tick`, `sync_connector`, `list_connector_runs`.

### Reports and exports

| Output                     | Route                                          | Notes                                       |
| -------------------------- | ---------------------------------------------- | ------------------------------------------- |
| Activity / SIEM            | `GET /api/v1/audit-log`                        | `category`, `include_requests` filters      |
| Executive PDF              | `GET /api/v1/snapshots/{id}/export.pdf`        | `Accept: application/pdf`                   |
| SPRS score                 | `GET /api/v1/gov-compliance/sprs`              | CMMC Level 2 from failing 800-171 practices |
| Audit readiness            | `GET /api/v1/platform/audit-readiness`         | audit-room score + workflow checklist       |
| AI governance              | `GET /api/v1/platform/ai-governance`           | model inventory, lineage, framework mapping |
| AI inventory               | `GET /api/v1/platform/ai-governance/inventory` | paginated model/agent inventory rows        |
| Remediation insight        | `GET /api/v1/insights/remediation`             | open/overdue task analytics                 |
| Scenario proof             | `security-lakehouse scenario run …`            | JSON report under `gold/scenario_reports/`  |
| OSCAL component definition | `GET /api/v1/oscal/component-definition`       | see [OSCAL_EXPORT.md](../OSCAL_EXPORT.md)   |
| OSCAL assessment results   | `GET /api/v1/oscal/assessment-results`         | see [OSCAL_EXPORT.md](../OSCAL_EXPORT.md)   |

## Agent Usage Pattern

Agents should:

1. Read `/api/v1/posture/current` first.
2. Inspect `/api/v1/control-tests` for evidence requirements, confidence inputs,
   and next action.
3. Inspect `/api/v1/violations` for owner/action detail.
4. Query `/api/v1/evidence/freshness?status=stale,expired,missing&sort=-age_minutes`
   before claiming that evidence is current.
5. Query `/api/v1/controls` for framework context.
6. Create `/api/v1/snapshots` only when the user asks for an audit, vendor,
   board, incident, or release-gate snapshot.
7. Use `/api/v1/agent-runs` for governed harness runs instead of invoking
   ad-hoc model calls. Include an `idempotency_key` for retry-safe scheduler,
   CI, and MCP clients.
8. Inspect `data_readiness.status` before acting on proposals; `needs_ingestion`
   means the account should sync/read existing lake data before trust conclusions.
9. Approve a specific stored proposal only after policy or human review. Retry
   approval calls safely; executed decisions return their previous execution
   result rather than duplicating work.

Agents should not infer compliance status from visual text. The API is the
contract.

MCP clients use the same contract. Local lake tools read posture, controls,
evidence, snapshots, and workflows from `TRUSTOPS_LAKE`; persisted agent-run
tools require `TRUSTOPS_API_URL` and `TRUSTOPS_API_KEY` so RBAC, tenant
isolation, approvals, and audit events stay behind the server boundary.

## Skills And Guardrails

TrustOps skills are small, auditable operating guides over this API and the lake
artifacts. A skill is not a hidden model prompt that invents controls. It is a
versioned contract that says what evidence it may read, what actions it may take,
what official sources it must cite, and what claims it must not make.

Recommended skill chain:

| Skill             | Reads                                           | Writes                                     | Guardrail                                                |
| ----------------- | ----------------------------------------------- | ------------------------------------------ | -------------------------------------------------------- |
| Ingestion skill   | source API or existing lake view                | raw connector evidence, bronze replay rows | read-only credentials; stable IDs; raw hash preserved    |
| Validation skill  | raw rows, connector run log                     | validation errors, normalized silver facts | fail closed on malformed records; no silent field drops  |
| Mapping skill     | silver facts, framework catalog                 | control/evidence links                     | source-linked mappings only; no invented controls        |
| Evaluation skill  | controls-as-code, freshness, evidence refs      | gold control tests, violations, confidence | deterministic rules; cite evidence refs and rule reasons |
| Remediation skill | violations, owners, SLA policy                  | task, evidence request, workflow run       | role-gated actions; no external calls unless allowlisted |
| Snapshot skill    | current posture and evidence refs               | immutable point-in-time snapshot           | user-requested reason; hash and audit event required     |
| Debug/log skill   | connector runs, validation errors, audit events | diagnostic summary                         | redacts secrets and role-restricted fields               |

At scale, these skills should run as scheduled jobs or workflow nodes, not as a
single autonomous blob. The control plane records who or what ran the skill,
which version was used, which inputs were read, which outputs changed, and which
audit event/correlation ID proves the action.

Skill manifests should include:

```yaml
name: evidence-ingestion
version: 0.2.0
role_required: security_admin
reads:
  - connector_config
  - source_api_or_lake_view
writes:
  - bronze/replay
  - connector_runs
tests:
  - fixture_replay
  - schema_validation
  - secret_redaction
  - idempotent_replay
```

## OCSF Boundary

TrustOps uses OCSF where OCSF is a good fit: cloud, identity, repository,
runtime, detection, vulnerability, and audit telemetry. It does not force OCSF
onto everything.

The canonical TrustOps model stays separate for:

- framework catalogs, source provenance, and control mappings
- evidence requirements and controls-as-code rules
- posture scores, confidence, freshness, exceptions, and owner SLAs
- remediation tasks, workflow runs, snapshots, trust shares, and audit boundary

That split is intentional. OCSF normalizes security facts; TrustOps models the
trust operation built on top of those facts. Connector and ingestion skills may
emit OCSF-shaped silver records when possible, plus TrustOps-specific fields
where needed for control evaluation and audit proof.

## Example

**Local development** (no auth required — `--allow-insecure-no-auth` disables the auth gate):

```bash
security-lakehouse serve --lake build/lakehouse --allow-insecure-no-auth --port 8787

curl -s http://127.0.0.1:8787/api/v1/posture/current | jq .
curl -s 'http://127.0.0.1:8787/api/v1/control-tests?result=fail&sort=-confidence_score&limit=10' | jq .
curl -s 'http://127.0.0.1:8787/api/v1/violations?severity=critical,high' | jq .
curl -s 'http://127.0.0.1:8787/api/v1/evidence/freshness?status=stale,expired,missing&sort=-age_minutes' | jq .
curl -s -X POST http://127.0.0.1:8787/api/v1/snapshots \
  -H 'content-type: application/json' \
  --data '{"reason":"vendor_due_diligence"}' | jq .
```

**Server deployment** (create an API key in the console under Settings → API keys):

```bash
export TRUSTOPS_TOKEN="tok_..."

curl -s -H "Authorization: Bearer $TRUSTOPS_TOKEN" \
  https://your-server/api/v1/posture/current | jq .

curl -s -H "Authorization: Bearer $TRUSTOPS_TOKEN" \
  'https://your-server/api/v1/control-tests?result=fail&sort=-confidence_score&limit=10' | jq .

curl -s -H "Authorization: Bearer $TRUSTOPS_TOKEN" \
  'https://your-server/api/v1/violations?severity=critical,high' | jq .

curl -s -H "Authorization: Bearer $TRUSTOPS_TOKEN" \
  'https://your-server/api/v1/evidence/freshness?status=stale,expired,missing&sort=-age_minutes' | jq .

curl -s -X POST -H "Authorization: Bearer $TRUSTOPS_TOKEN" \
  -H 'content-type: application/json' \
  --data '{"reason":"vendor_due_diligence"}' \
  https://your-server/api/v1/snapshots | jq .
```

### Review identity and workflow decision conflicts

Browser sessions exchanged from API keys retain their originating key and its
workspace. Expiration, revocation, deletion, or missing legacy provenance
invalidates derived access. Such sessions cannot perform human-reserved mapping
or workpaper reviews; eligible OIDC/SAML identities must sign in directly.
Administrators may issue keys for their own identity only.

Workflow approval consumes a pending decision before executing downstream
nodes. The claim binds the reviewed workflow version and content. Replayed,
rejected, or changed decisions return 409. An interrupted claim also returns 409
on approval or retry: an operator must reconcile any external effects before
starting a replacement run. Historical run records remain append-only; older
pending runs without a content binding require a new review run.
