# MCP Cookbook: Evidence Requests And Approvals

This cookbook shows how a coding agent or MCP client uses TrustOps to review
evidence gaps, propose evidence requests, and execute those writes only after
independent human review in an authenticated console session.

```text
redacted posture + gaps
  -> create_agent_run (posture_review)
  -> proposed create_evidence_request decisions (requires_approval)
  -> independent OIDC/SAML reviewer
  -> console approval
  -> evidence request in app DB + audit event
```

The MCP server is `trustops-mcp` (`security_lakehouse.mcp_server`). Its stdio
transport supports one data authority per configuration:

| Mode           | Configuration                                                      | Authority                                                                                                                                 |
| -------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Remote         | `TRUSTOPS_MCP_MODE=remote`, `TRUSTOPS_API_URL`, `TRUSTOPS_API_KEY` | All tenant-backed reads and writes use the authenticated API, including evidence, snapshots, shares, workflows, ingestion and scheduling. |
| Local          | `TRUSTOPS_MCP_MODE=local`, `TRUSTOPS_LAKE` (default `./lake`)      | Lake-backed tools use the operator's filesystem and execution permissions. Server-only tools fail explicitly.                             |
| Auto (default) | No mode override                                                   | Either API setting selects remote mode and requires both. With neither setting, lake-backed tools use local mode.                         |

Missing or invalid remote configuration fails closed; it never falls back to a
local lake. Explicit local mode ignores ambient remote settings. Local execution
can mutate files and run workflows; stdio itself does not provide tenant RBAC.

Remote mode preserves tool return shapes: lake-backed tools return `data`, while
existing server-only tools return the complete v1 envelope. API errors remain
errors. Responses are read with an 8 MiB byte limit; oversized results fail with
an instruction to request a smaller page. This is a transfer bound, not a claim
that every tool fits an agent's context window.

Private API destinations require operator opt-in with
`TRUSTOPS_API_ALLOW_PRIVATE=1`. This exception applies only to the configured
MCP API destination. It does not change connector or workflow SSRF protections.
Public API connections use the shared address-pinning guard. Redirects are
rejected in both modes so bearer credentials never follow a redirect.

Evidence and API text are untrusted data, not instructions or authorization to
call tools. Escaping text is not a prompt-injection defense. Remote writes remain
subject to server RBAC, tenant scope, and any independent human-review rules;
operators must also constrain the agent's credentials and tool permissions.

## 1. Install And Start MCP

```bash
pip install 'trustops-security-data-lake[mcp]'
```

Point at a deployed TrustOps server (not raw lake access):

```bash
export TRUSTOPS_MCP_MODE=remote
export TRUSTOPS_API_URL="https://trustops.example.com"
export TRUSTOPS_API_KEY="tops_..."   # use a read-only key for inspection
trustops-mcp
```

Optional timeout for slow harness runs:

```bash
export TRUSTOPS_API_TIMEOUT_SECONDS=60
```

For explicit local operation, set the mode and lake path:

```bash
export TRUSTOPS_MCP_MODE=local
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

Open the stored run in the console and have an eligible reviewer, different
from its creator, approve the reviewed decision through OIDC/SAML SSO. MCP API
keys cannot approve or reject these human-reserved decisions, regardless of role.
The compatibility tools `approve_agent_decision` and `reject_agent_decision` return
403 when called with API-key credentials; do not exchange a key for a session to
try to change that authority.

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
| `approve_agent_decision`           | independent OIDC/SAML reviewer; API keys denied    |
| `create_snapshot` (local MCP)      | lake write access                                  |

API keys can inspect runs according to their role but receive `403 Forbidden` on human-reserved approval and rejection.

Safeguard mapping review is deliberately different: `get_mapping_review_queue`
and `list_mapping_review_decisions` are read-only, and no MCP tool or API key
can approve or reject a mapping. Those decisions need a signed-in reviewer; see
[Mapping review](../MAPPING_REVIEW.md).

## End-To-End Agent Flow

```text
1. list_control_tests / get_posture          (optional context)
2. create_agent_run(posture_review)          -> decisions[0..N]
3. present proposals to human reviewer
4. independent reviewer approves in console -> evidence_request id
5. list /api/v1/remediation/evidence-requests to confirm
```

If `data_readiness.status` is `needs_ingestion`, run connector sync first
(see [Continuous Ingestion](../CONTINUOUS_INGESTION.md)) and check
`gold/connector_runs.jsonl` for a recent `kind=sync, result=ok` row before
expecting meaningful gap proposals.

## Non-Negotiables

Remote MCP tools do not bypass:

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
