---
name: trustops-operator
description: >-
  Operate GRC Lake through its MCP tools or versioned API to collect security
  evidence, inspect asset and AI inventory, evaluate controls, triage findings,
  prepare owner actions and export assessment evidence. Use for GRC Lake
  workflows; conclusions must remain bounded by observed scope and coverage.
---

# GRC Lake operator

Use the configured GRC Lake MCP server or API. Discover the available contract
with `describe_api` or `GET /api/v1` before selecting tools; tool availability and
permissions can differ by deployment. Prefer an authenticated remote API for
shared environments. Local-lake mode relies on filesystem access and is suited
to a trusted local workspace.

## Establish scope and evidence

Read `get_ingestion_status`, `get_posture`, `list_assets`, `list_evidence` and
`list_frameworks` as needed. Paginate list results; a first page is not a complete
inventory. Report tenant, source scope, observation time, failed or incomplete
collection and stale evidence before interpreting posture. Preserve unknown
asset owners, environments and business impacts as unknown.

Inventory may include cloud assets, models, agents and AI services when the
configured sources provide those facts. A listed connector or framework is not
proof it has collected or evaluated that scope. Describe gaps explicitly.

## Collect and evaluate

For an authorized collection request, discover and probe the chosen source,
configure its agreed scope, then sync and inspect the resulting run status.
Use the deployment's existing credential mechanism: workload identity,
federation or short-lived provider tokens where supported. Do not ask for raw
secrets in chat, print them, embed them in requests or artifacts, or store them
in this repository. A credential reference identifies a configured secret; it
is not the secret value. Never claim all authentication is short-lived without
checking that deployment's actual configuration.

Call `run_lake_eval` only for the authorized lake scope. If collection is
incomplete or normalization rejects a mapping or rule, report the failure and
the age of the last successful assessment. Do not treat retained older posture
as a successful evaluation of the failed run. Preserve supplied rule meaning;
never substitute a permissive rule to obtain a verdict.

## Interpret and triage

Trace framework requirement → safeguard → rule → evidence → result. Distinguish
catalogued, mapped, proposed, reviewed, evaluated and passing coverage. A pass is
an outcome for that rule and evidence scope; it does not establish certification
or complete framework compliance. Use official sources for requirement claims.

Use observed severity with production/customer exposure, business impact,
owner and evidence freshness to explain priority. Cite evidence IDs or safe
references, source timestamps and assessment identifiers. Avoid exposing raw
payloads or private account identifiers in public output. Separate deterministic
findings from an agent's analysis and remediation suggestions.

## Act and verify

Prepare owner actions or evidence requests using the documented API/MCP tool
and the user's existing authorization. Approval permissions are not proof of
approval: preserve any required reviewer decision and audit record. Do not
approve an agent's own proposal merely because the agent can call an approval
tool. External remediation and sharing require authorization for that action.

Read back a created task, request, approved action or snapshot and report its ID
and actual state. A submitted task is not a resolved finding. Verify a fresh
assessment before claiming a fix. For exports, check snapshot integrity and
state scope and freshness; do not publish private evidence automatically.

If a call fails, report its safe error category and retain the last successful
state. Use the same idempotency key for a retry of the same logical mutation
where that endpoint supports it. Do not invent an idempotency guarantee for an
endpoint that has not documented or demonstrated one.
