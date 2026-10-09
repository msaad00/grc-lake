# Headless GRC Architecture

GRC Lake is **headless-first**: compliance posture, evidence, controls, and audit
artifacts are produced and consumed through **APIs, CLI, MCP, and CI** — the same
deterministic lake and `/api/v1` contract everywhere. The web console is a **peer
surface** for human reviewers, auditors, and operators — not the source of truth.

This mirrors how modern security platforms moved to agent-driven, API-native
operations: automation runs continuously; humans inspect, approve, and sign off.

## Surfaces (one core)

| Surface          | Primary caller               | Role                                                              |
| ---------------- | ---------------------------- | ----------------------------------------------------------------- |
| **REST API**     | CI, scripts, integrations    | Read posture, write gated mutations                               |
| **CLI**          | Operators, runbooks          | Lake rebuild, connector sync, snapshots                           |
| **MCP / agents** | SOC, GRC, remediation agents | Remote tools use API-key RBAC; local tools use operator authority |
| **Scheduler**    | CronJob / K8s                | Connector sync, workflow ticks                                    |
| **Console**      | GRC leads, auditors          | Visual drill-down, approvals, trust shares                        |

All surfaces read the **same JSON** from the customer lake. Agents must not bypass
approval gates for remediation, trust shares, or workflow side effects.

## Headless workflows

### Connect read-only (default — no customer SDL required)

Most teams use **direct API connectors** (`github-security`, `aws-posture`,
`okta-identity`, …): agentless, read-only, same probe-gated flow as the console.
You do not need Snowflake or a security data lake first.

Step-by-step curl, CLI, and MCP: [playbooks/HEADLESS_CONNECTOR_SETUP.md](playbooks/HEADLESS_CONNECTOR_SETUP.md).

Optional **existing-lake readers** (Snowflake, ClickHouse) apply only when evidence
is already materialized in customer-owned stores.

### Continuous source sync

Connectors **discover → probe → enable → sync** on schedule; control eval runs on a
separate `eval_schedule`. Raw evidence upserts by `event_id`; gold posture
materializes without console interaction. See [CONTINUOUS_INGESTION.md](CONTINUOUS_INGESTION.md).

### Posture gates in CI

Use API keys and correlation IDs to fail builds or deployments when control tests
fail or violations exceed thresholds. See [playbooks/CI_POSTURE_GATE.md](playbooks/CI_POSTURE_GATE.md)
and [api/AGENT_API.md](api/AGENT_API.md).

### Agent remediation (approval-gated)

SOC agents propose triage and remediation via MCP; human or policy approval applies
changes. Audit rows carry stable `event_id` and UTC `occurred_at`.

### Audit export

`GET /api/v1/audit-log` returns a unified activity envelope for SIEM export,
compliance archives, and auditor packages — no UI scrape required.

MCP tools wrap the same surface:

| Cluster        | Tools                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Ingestion loop | `get_ingestion_status`, `list_eval_runs`, `run_lake_eval`, `run_scheduler_tick`, `list_connectors`, `probe_connector`, `discover_connector`, `configure_connector`, `sync_connector`, `list_connector_runs`                                                                                                                                                                                                                                                                                                                                                         |
| Posture / lake | `get_posture`, `posture_as_of`, `list_controls`, `list_evidence`, `list_evidence_freshness`, `list_violations`, `get_framework_detail`, `get_snapshots_integrity`, `get_snapshot_detail`, `get_tracking_integrity`, `get_ai_governance`, `list_ai_inventory`, `describe_api`                                                                                                                                                                                                                                                                                        |
| Audit / export | `list_audit_log`, `create_snapshot`, `list_snapshots`, `create_trust_share`, `list_trust_shares`, `get_audit_readiness`, `get_evidence_freshness_summary`, `capture_insights_point`                                                                                                                                                                                                                                                                                                                                                                                 |
| GRC programs   | `adopt_policy`, `publish_policy`, `acknowledge_policy`, `create_risk`, `update_risk`, `delete_risk`, `list_risks`, `create_remediation_task`, `update_remediation_task`, `update_evidence_request`, `create_remediation_exception`, `revoke_remediation_exception`, `create_poam_item`, `update_poam_item`, `attach_tag`, `detach_tag`, `create_vendor_assessment`, `submit_vendor_assessment`, `create_access_review`, `seed_access_review`, `record_access_review_decision`, `get_policy_template`, `get_policy`, `get_access_review`, `get_vendor_assessment`, … |
| Agent harness  | `list_agent_runs`, `create_agent_run`, `approve_agent_decision`, `reject_agent_decision`                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |

Use `describe_api` to enumerate the full `/api/v1` catalog.

### Point-in-time snapshots

Assessment snapshots with hash chain support auditor sign-off and drift detection
via API or CLI.

## Human console (when you need it)

The console exists for:

- Executive and audit-room dashboards
- Framework drill-down (control → rule → evidence → datasource)
- Access review campaigns and evidence requests
- Trust-center shares for external auditors
- Workflow canvas inspection and approvals

Console actions hit the **same API** as headless callers and appear in request audit.

## MCP local trust boundary

`grc-lake-mcp` can run in two modes:

| Mode              | Env                                        | RBAC                                                               | Typical use                                         |
| ----------------- | ------------------------------------------ | ------------------------------------------------------------------ | --------------------------------------------------- |
| **Local lake**    | `GRC_LAKE_MCP_MODE=local`, `GRC_LAKE_LAKE` | Application RBAC **not** enforced for lake-backed read/write tools | Developer laptop, CI job with dedicated lake volume |
| **Remote server** | `GRC_LAKE_API_URL` + `GRC_LAKE_API_KEY`    | Same scopes as API keys (`read`, `write`, `admin`, …)              | Shared hosts, multi-tenant server mode              |

**In local mode, lake-backed write tools** (`create_snapshot`, `sync_connector`, `configure_connector`, `run_workflow`, `run_scheduler_tick`, `create_trust_share`, …) mutate files under `GRC_LAKE_LAKE` directly. They do not pass through FastAPI identity checks — security relies on **who can run the MCP process** and **filesystem permissions** on the lake directory.

**In local mode, lake-backed read tools** (`get_posture`, `get_ai_governance`, `list_evidence`, …) read the same JSONL artifacts as `GET /api/v1/*` without a bearer token.

**In remote mode, all tenant-backed tools** use the authenticated API, including
posture, evidence, connectors, shares, snapshots, workflows, and scheduling.
Either `GRC_LAKE_API_URL` or `GRC_LAKE_API_KEY` selects remote mode by default;
both are required, and partial configuration fails closed. Explicit
`GRC_LAKE_MCP_MODE=local` disables remote-only tools. Private API destinations
require `GRC_LAKE_API_ALLOW_PRIVATE=1`; other outbound SSRF protections are
unchanged. See the [MCP cookbook](cookbook/MCP_EVIDENCE_AND_APPROVALS.md).

### Deployment guidance

1. On shared machines, prefer **remote API mode** for MCP agents so writes are RBAC-gated and request-audited.
2. When using local mode, run MCP under a **dedicated service account** with minimal lake ACL (no world-readable `gold/` or `silver/`).
3. Never point `GRC_LAKE_LAKE` at a production lake path from an untrusted stdio client (IDE plugins, unvetted agent hosts).
4. Rotate API keys used for remote MCP the same as CI deploy keys.

## Idempotency and traceability

| Concern          | Mechanism                                |
| ---------------- | ---------------------------------------- |
| Duplicate writes | `Idempotency-Key` on mutating APIs       |
| Evidence dedupe  | `event_id` on raw connector events       |
| Request tracing  | `X-Correlation-ID` (one attempt per row) |
| Audit integrity  | Chained triage log + UUID request audit  |

See [INGESTION_CONNECTORS_IDEMPOTENCY.md](INGESTION_CONNECTORS_IDEMPOTENCY.md).

## Related

- [AUDIT_READINESS.md](AUDIT_READINESS.md) — audit-room score and workflow checklist
- [AUDIT_SCALE.md](AUDIT_SCALE.md) — large-finding workloads
- [CONNECTORS.md](CONNECTORS.md) — connector catalog and registry model
- [playbooks/HEADLESS_CONNECTOR_SETUP.md](playbooks/HEADLESS_CONNECTOR_SETUP.md) — curl/CLI/MCP connect flow
- [api/AGENT_SKILLS.md](api/AGENT_SKILLS.md) — agent skill catalog + OpenAPI
