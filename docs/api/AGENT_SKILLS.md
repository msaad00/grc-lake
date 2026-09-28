# Agent Skill Catalog

Composable **skills** for coding agents, CI jobs, and MCP clients. Each skill maps
intent → `/api/v1` routes → MCP tools → example payloads.

TrustOps is **headless-first**: run these without the console. The human workbench
is a peer surface on the same contracts.

Related: [AGENT_API.md](AGENT_API.md) · [openapi.v1.json](openapi.v1.json) ·
[HEADLESS_CONNECTOR_SETUP.md](../playbooks/HEADLESS_CONNECTOR_SETUP.md)

## Portable agent skills

The repository includes [TrustOps operator](../../agent-skills/trustops-operator/SKILL.md)
and six [analyst skills](../../agent-skills/FRAMEWORK_SKILLS.md). Copy the chosen
skill folder into the skill search path supported by your agent client, and
configure access to your TrustOps deployment separately. These Markdown skills
provide instructions; they do not grant API permissions or install credentials.

## Quick discovery

```bash
# Machine-readable catalog (requires API key)
curl -sS "$TRUSTOPS_API_URL/api/v1" -H "Authorization: Bearer $TRUSTOPS_API_KEY" | jq .

# OpenAPI schema (no auth on local dev server)
curl -sS "$TRUSTOPS_API_URL/openapi.json" | jq .info

# MCP
describe_api
```

Regenerate committed artifacts: `make openapi-export`

**Full route catalog:** [resource-catalog.v1.json](resource-catalog.v1.json) (all
`/api/v1` dispatch routes). **OpenAPI:** [openapi.v1.json](openapi.v1.json)
(FastAPI-registered routes only).

---

## Skill: `ingestion.connect`

**Intent:** Connect a read-only source (agentless — no customer SDL required),
validate access, enable collection, sync evidence, run control eval.

**Default path:** direct API connectors (`github-security`, `aws-posture`, …).

| Step           | REST                                     | MCP tool              |
| -------------- | ---------------------------------------- | --------------------- |
| List catalog   | `GET /api/v1/connectors`                 | `list_connectors`     |
| Discover scope | `POST /api/v1/connectors/{id}/discover`  | `discover_connector`  |
| Test access    | `POST /api/v1/connectors/{id}/probe`     | `probe_connector`     |
| Enable         | `POST /api/v1/connectors/{id}/configure` | `configure_connector` |
| Sync           | `POST /api/v1/connectors/{id}/sync`      | `sync_connector`      |
| Control eval   | `POST /api/v1/ingestion/eval`            | `run_lake_eval`       |
| Scheduler      | `POST /api/v1/scheduler/tick`            | `run_scheduler_tick`  |

**Scope:** `connector_manage` for mutate steps; `read` for list/status.

Inspect sync completion before evaluation. A pagination cap or failed required
source read is an error, not a successful partial inventory; retained posture
still describes the prior successful assessment. Invalid mapping/rule validation
must stop the run rather than substitute a different rule.

**Example (GitHub Security):**

```bash
export CORR="agent-connect-$(date +%s)"

curl -sS -X POST "$TRUSTOPS_API_URL/api/v1/connectors/github-security/probe" \
  -H "Authorization: Bearer $TRUSTOPS_API_KEY" \
  -H "Content-Type: application/json" \
  -H "X-Correlation-ID: $CORR" \
  -d '{
    "actor": "coding-agent",
    "credentials": {"credential_ref": "TRUSTOPS_GITHUB_APP_INSTALLATION_TOKEN"},
    "options": {"repo": "acme/platform"}
  }'

curl -sS -X POST "$TRUSTOPS_API_URL/api/v1/connectors/github-security/configure" \
  -H "Authorization: Bearer $TRUSTOPS_API_KEY" \
  -H "Content-Type: application/json" \
  -H "X-Correlation-ID: $CORR" \
  -d '{"state":"enabled","actor":"coding-agent","credentials":{"credential_ref":"TRUSTOPS_GITHUB_APP_INSTALLATION_TOKEN"},"options":{"repo":"acme/platform"}}'

curl -sS -X POST "$TRUSTOPS_API_URL/api/v1/connectors/github-security/sync" \
  -H "Authorization: Bearer $TRUSTOPS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"actor":"coding-agent"}'

curl -sS -X POST "$TRUSTOPS_API_URL/api/v1/ingestion/eval" \
  -H "Authorization: Bearer $TRUSTOPS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"actor":"coding-agent"}'
```

Full walkthrough: [HEADLESS_CONNECTOR_SETUP.md](../playbooks/HEADLESS_CONNECTOR_SETUP.md).

---

## Skill: `posture.read`

**Intent:** Explain current trust posture, failing control tests, and open
violations — read-only; redact private evidence before including it in agent output.

| Resource         | REST                                    | MCP tool                  |
| ---------------- | --------------------------------------- | ------------------------- |
| Posture summary  | `GET /api/v1/posture/current`           | `get_posture`             |
| Point-in-time    | `GET /api/v1/posture/as-of`             | `posture_as_of`           |
| Control tests    | `GET /api/v1/control-tests?result=fail` | (via SDK / fetch)         |
| Violations       | `GET /api/v1/violations`                | `list_violations`         |
| Evidence         | `GET /api/v1/evidence`                  | `list_evidence`           |
| Freshness        | `GET /api/v1/evidence/freshness`        | `list_evidence_freshness` |
| Ingestion health | `GET /api/v1/ingestion/status`          | `get_ingestion_status`    |
| Audit readiness  | `GET /api/v1/platform/audit-readiness`  | `get_audit_readiness`     |

**Scope:** `read`

**Example:**

```bash
curl -sS "$TRUSTOPS_API_URL/api/v1/posture/current" \
  -H "Authorization: Bearer $TRUSTOPS_API_KEY" | jq '.data.posture'

curl -sS "$TRUSTOPS_API_URL/api/v1/control-tests?result=fail&limit=10" \
  -H "Authorization: Bearer $TRUSTOPS_API_KEY" | jq '.data[] | {control_id, result, owner}'
```

---

## Skill: `audit.prove`

**Intent:** Produce auditor-ready artifacts — snapshots, trust shares, activity
export — usually after explicit human or policy approval.

| Action          | REST                                    | MCP tool                  |
| --------------- | --------------------------------------- | ------------------------- |
| Create snapshot | `POST /api/v1/snapshots`                | `create_snapshot`         |
| List snapshots  | `GET /api/v1/snapshots`                 | `list_snapshots`          |
| Snapshot detail | `GET /api/v1/snapshots/{id}`            | `get_snapshot_detail`     |
| Executive PDF   | `GET /api/v1/snapshots/{id}/export.pdf` | —                         |
| Trust share     | `POST /api/v1/trust-shares`             | `create_trust_share`      |
| Activity log    | `GET /api/v1/audit-log`                 | `list_audit_log`          |
| Integrity       | `GET /api/v1/snapshots/integrity`       | `get_snapshots_integrity` |

**Scope:** `read` for list/export; `write` or `admin` for create/revoke.

For portable normalized evidence, authorized local agents can use
[`pipeline export-parquet`](../PARQUET_EXPORT.md) or
[`pipeline publish-iceberg`](../ICEBERG_REST.md). These are CLI operations, not
REST/MCP endpoints. Verify the tenant and generation, confirm authorization for
the destination, and retain the export manifest or snapshot receipt. A row count
or successful publication does not establish collection completeness or framework
compliance. Supply catalog bearer tokens through a process environment supplied
by the identity broker; do not put tokens in prompts, command arguments, or reports.

**Example:**

```bash
curl -sS -X POST "$TRUSTOPS_API_URL/api/v1/snapshots" \
  -H "Authorization: Bearer $TRUSTOPS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"reason":"quarterly_audit","actor":"grc-agent"}'
```

---

## Skill: `remediate.propose`

**Intent:** Propose governed remediation via the agent harness — evaluations and
write proposals stay **approval-gated** until a human approves.

| Action           | REST                                                 | MCP tool                  |
| ---------------- | ---------------------------------------------------- | ------------------------- |
| Run harness      | `POST /api/v1/agent-runs`                            | `create_agent_run`        |
| Inspect run      | `GET /api/v1/agent-runs/{id}`                        | (SDK)                     |
| Approve decision | `POST /api/v1/agent-runs/{id}/decisions/{i}/approve` | `approve_agent_decision`  |
| Reject decision  | `POST /api/v1/agent-runs/{id}/decisions/{i}/reject`  | `reject_agent_decision`   |
| Remediation task | `POST /api/v1/remediation/tasks`                     | `create_remediation_task` |
| Evidence request | `POST /api/v1/remediation/evidence-requests`         | —                         |

**Scope:** `agents` for harness; `write` for approved side effects.

**Example (rules-only posture review):**

```bash
curl -sS -X POST "$TRUSTOPS_API_URL/api/v1/agent-runs" \
  -H "Authorization: Bearer $TRUSTOPS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "harness": "posture_review",
    "objective": "summarize failing controls for SOC2",
    "role": "analyst",
    "use_model": false,
    "idempotency_key": "posture-review-2026-07-12"
  }'
```

Console: `/console/agents/` — same routes with curl builder.

---

## Skill: `ci.gate`

**Intent:** Fail CI/CD when posture regresses — read-only gate for platform engineers.

| Check                  | REST                                              | Threshold input             |
| ---------------------- | ------------------------------------------------- | --------------------------- |
| Posture score          | `GET /api/v1/posture/current`                     | `min-score`                 |
| Critical violations    | posture summary                                   | `max-critical-violations`   |
| **Control regression** | posture + `GET /api/v1/control-tests?result=fail` | `max-failing-control-tests` |
| Stale evidence         | posture freshness                                 | `fail-on-stale-evidence`    |

**Scope:** `read` (optional `write` only for post-pass snapshot)

**GitHub Action:**

```yaml
- uses: msaad00/trustops-security-data-lake/.github/actions/posture-gate@v0.2.19
  with:
    trustops-url: ${{ secrets.TRUSTOPS_URL }}
    api-token: ${{ secrets.TRUSTOPS_API_TOKEN }}
    correlation-id: deploy-${{ github.run_id }}
    min-score: "70"
    max-failing-control-tests: "0"
```

**Shell:**

```bash
TRUSTOPS_URL="$TRUSTOPS_API_URL" \
CORRELATION_ID="ci-$(date +%s)" \
MAX_FAILING_CONTROL_TESTS=0 \
./tools/ci/posture-gate.sh
```

Playbook: [CI_POSTURE_GATE.md](../playbooks/CI_POSTURE_GATE.md)

---

## Headers agents should send

| Header                            | When                                                                                                               |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `Authorization: Bearer <api_key>` | Always (except local `--allow-insecure-no-auth`)                                                                   |
| `X-Correlation-ID`                | Every mutating call — one ID per logical attempt                                                                   |
| `Idempotency-Key`                 | Only when the specific endpoint documents replay handling; inspect existing state before retrying other mutations. |

## MCP vs REST

| Mode       | Env                                     | RBAC                                    |
| ---------- | --------------------------------------- | --------------------------------------- |
| Remote API | `TRUSTOPS_API_URL` + `TRUSTOPS_API_KEY` | Enforced — **preferred for agents**     |
| Local lake | `TRUSTOPS_LAKE`                         | Filesystem trust boundary — dev/CI only |

See [HEADLESS_GRC.md](../HEADLESS_GRC.md#mcp-local-trust-boundary).

## OpenAPI and resource catalog

| Artifact                                             | Contents                                                                   |
| ---------------------------------------------------- | -------------------------------------------------------------------------- |
| [resource-catalog.v1.json](resource-catalog.v1.json) | Full `/api/v1` self-describing catalog (connector probe, posture, eval, …) |
| [openapi.v1.json](openapi.v1.json)                   | FastAPI OpenAPI schema (auth, agent-runs, remediation, …)                  |

Live server also serves `/openapi.json`. CI validates both committed files match
generators (`make openapi-export`).
