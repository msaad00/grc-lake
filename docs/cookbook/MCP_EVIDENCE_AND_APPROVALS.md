# MCP Cookbook: Evidence Requests And Approvals

This cookbook shows how a coding agent or MCP client uses TrustOps to review
evidence gaps, propose evidence requests, and execute those writes only after
human or policy approval.

```text
redacted posture + gaps
  -> create_agent_run (posture_review)
  -> proposed create_evidence_request decisions (requires_approval)
  -> human/policy review
  -> approve_agent_decision
  -> evidence request in app DB + audit event
```

The MCP server is `trustops-mcp` (`security_lakehouse.mcp_server`). It exposes
two transport surfaces:

| Surface              | Env vars                               | Tools                                                                                                                            |
| -------------------- | -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Local lake reads     | `TRUSTOPS_LAKE` (default `./lake`)     | `get_posture`, `list_controls`, `list_evidence`, `create_snapshot`, …                                                            |
| Ingestion loop       | `TRUSTOPS_LAKE`                        | `get_ingestion_status`, `list_eval_runs`, `run_lake_eval`, `run_scheduler_tick`, `sync_connector`                                |
| Authenticated server | `TRUSTOPS_API_URL`, `TRUSTOPS_API_KEY` | `list_agent_runs`, `create_agent_run`, `get_agent_run`, `approve_agent_decision`, `reject_agent_decision`                        |
| Lake-backed reads    | same as authenticated server           | When both env vars are set, `get_ai_governance` and `list_ai_inventory` route through the server API instead of local lake files |

Evidence-request approvals are **server-backed**. They call the same
`/api/v1/agent-runs*` contract as the console and curl examples in
[Agent Harness](../AGENT_HARNESS.md).

## 1. Install And Start MCP

```bash
pip install 'trustops-security-data-lake[mcp]'
```

Point at a deployed TrustOps server (not raw lake access):

```bash
export TRUSTOPS_API_URL="https://trustops.example.com"
export TRUSTOPS_API_KEY="tops_..."   # contributor or higher for approvals
trustops-mcp
```

Optional timeout for slow harness runs:

```bash
export TRUSTOPS_API_TIMEOUT_SECONDS=60
```

For local lake reads only (no approvals), set the lake path:

```bash
export TRUSTOPS_LAKE="/lake"   # Helm default; local demos often use build/lakehouse
trustops-mcp
```

Install the MCP server in Cursor, Claude Desktop, or another MCP host using
stdio transport and the env vars above. Copy
[`examples/mcp/mcp.json.example`](../../examples/mcp/mcp.json.example) as a starting point.

The server advertises **TrustOps icons** on `serverInfo` and each tool (MCP
SEP-973). Hosted deployments should set `TRUSTOPS_PUBLIC_URL` so clients can
load `https://<host>/brand/trustops-mark.svg`. Stdio mode embeds the SVG as a
data URI fallback.

## 2. Run A Posture Review Harness

Use `create_agent_run` with harness `posture_review`. The server resolves the
tenant lake from auth context — do not pass machine paths through MCP.

```json
{
  "harness": "posture_review",
  "objective": "Review evidence gaps before customer audit.",
  "role": "read_only",
  "orchestrator": "sequential",
  "idempotency_key": "posture-review-2026-07-03"
}
```

The response envelope includes:

- `data.id` — run id for follow-up calls
- `data.evaluation` — deterministic score, confidence, and coverage
- `data.decisions[]` — proposed actions, each with `requires_approval: true`
- `data.data_readiness` — whether connectors need sync first (`lake_ready`,
  `partial_lake`, or `needs_ingestion`)

Reusing the same `idempotency_key` returns the stored run instead of rerunning
the harness. This makes scheduler and agent retries safe.

Inspect one run:

```json
{ "run_id": "<RUN_ID>" }
```

via `get_agent_run`.

## 3. Identify Evidence-Request Proposals

Filter decisions where `action` is `create_evidence_request`:

```json
{
  "action": "create_evidence_request",
  "status": "pending",
  "requires_approval": true,
  "payload": {
    "control_id": "SOC2-CC6.1",
    "requested_from": "security-platform",
    "note": "Missing identity.access_review evidence."
  }
}
```

Other executable proposal types (also approval-gated):

- `create_remediation_task`
- `create_soc_case` (stored as an internal remediation task)
- `assign_owner` (stored as an internal remediation task)
- `freeze_snapshot` (requires `snapshot` scope on the API key)

External actions (webhooks, Slack, ticketing) are **not** executed by agent
approval. Route those through the workflow engine.

## 4. Approve One Decision

Call `approve_agent_decision` with the run id and zero-based decision index:

```json
{
  "run_id": "<RUN_ID>",
  "decision_index": 0,
  "note": "Approved for Q3 audit prep."
}
```

This maps to:

```bash
curl -s -X POST "$TRUSTOPS_API_URL/api/v1/agent-runs/$RUN_ID/decisions/0/approve" \
  -H "authorization: Bearer $TRUSTOPS_API_KEY" \
  -H "content-type: application/json" \
  --data '{"note":"Approved for Q3 audit prep."}' | jq .
```

On success the server:

1. writes an evidence request row to the application-state DB
   (`evidence_requests` table under `<lake>/server/app.db` or
   `TRUSTOPS_DATABASE_URL`);
2. marks the decision `executed` with `execution_result.type`:
   `evidence_request`;
3. records the approver identity and note in audit.

Approval is idempotent. Retrying an already executed decision returns
`meta.executed: false` and the stored `execution_result` without creating a
duplicate request.

To decline a proposal instead, call `reject_agent_decision` with a reason
(`POST .../decisions/{i}/reject`, body `{"reason": "..."}`). The decision is
marked `rejected` with the rejecting identity and reason and is never executed;
approving it afterwards returns `409`, as does rejecting an executed decision.

## 5. Verify The Evidence Request

List requests through the API or MCP host's HTTP bridge:

```bash
curl -s "$TRUSTOPS_API_URL/api/v1/remediation/evidence-requests" \
  -H "authorization: Bearer $TRUSTOPS_API_KEY" | jq .
```

Or open `/console/remediation/` in the TrustOps console.

## RBAC And Scopes

| Action                             | Minimum role / scope                               |
| ---------------------------------- | -------------------------------------------------- |
| `create_agent_run`                 | write scope (e.g. `contributor`, `security_admin`) |
| `get_agent_run`, `list_agent_runs` | read scope                                         |
| `approve_agent_decision`           | write scope                                        |
| `create_snapshot` (local MCP)      | lake write access                                  |

`read_only` keys can inspect runs but receive `403 Forbidden` on approve.

Safeguard mapping review is deliberately different: `get_mapping_review_queue`
and `list_mapping_review_decisions` are read-only, and no MCP tool or API key
can approve or reject a mapping. Those decisions need a signed-in reviewer; see
[Mapping review](../MAPPING_REVIEW.md).

## End-To-End Agent Flow

```text
1. list_control_tests / get_posture          (optional context)
2. create_agent_run(posture_review)          -> decisions[0..N]
3. present proposals to human reviewer
4. approve_agent_decision(run_id, index)     -> evidence_request id
5. list /api/v1/remediation/evidence-requests to confirm
```

If `data_readiness.status` is `needs_ingestion`, run connector sync first
(see [Continuous Ingestion](../CONTINUOUS_INGESTION.md)) and check
`gold/connector_runs.jsonl` for a recent `kind=sync, result=ok` row before
expecting meaningful gap proposals.

## Non-Negotiables

MCP tools do not bypass:

- tenant isolation and RBAC
- redaction policy on harness inputs
- data-readiness preflight
- approval before allowlisted writes
- idempotency on runs and decisions
- audit logging

The model (if enabled server-side via `TRUSTOPS_AGENT_USE_MODEL=1`) may
summarize or rank proposals. It cannot mark controls passing, mutate evidence,
or execute writes without approval.

## Related Docs

- [Agent Harness](../AGENT_HARNESS.md) — harness contract and curl examples
- [Agent API](../api/AGENT_API.md) — full `/api/v1/agent-runs` surface
- [Connectors](../CONNECTORS.md) — sync history in `gold/connector_runs.jsonl`
- [Server Auth](../SERVER_AUTH.md) — API keys, roles, and scopes
