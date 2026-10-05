# Agent Harness

TrustOps can run human and headless agent workflows without moving compliance
truth into an LLM.

The core remains deterministic:

```text
connectors -> evidence -> assets -> controls -> mappings -> posture -> snapshots -> trust shares -> audit
```

The optional agent harness wraps that core:

```text
redacted TrustOps facts -> deterministic tools -> optional model context -> proposed actions -> approval -> TrustOps API write -> audit event
```

This document is not the harness. It is the operator contract. The executable
harness lives in `src/security_lakehouse/agents/`, and the behavior is locked
by `tests/test_agents.py`.

## Package shape

The first harness lives under `security_lakehouse.agents`:

- `budgets.py` enforces context size, fact count, and output-token budgets
  before any optional provider call.
- `providers.py` reads optional model configuration from environment.
- `state.py` defines the shared agent run state and action proposal record.
- `tools.py` exposes typed, redaction-aware TrustOps fact readers.
- `model_contract.py` builds the model-safe prompt/context and validates
  model-proposed tool calls.
- `model_client.py` contains dependency-free optional provider clients for
  Ollama, OpenAI-compatible APIs, and Anthropic.
- `evaluations.py` computes deterministic harness checks, failures, coverage,
  score, confidence, and risk level from TrustOps state.
- `graphs.py` runs the first posture-review flow sequentially or through a
  LangGraph graph when `trustops-security-data-lake[agents]` is installed.

## LangGraph orchestration (optional)

LangGraph is **orchestration only** in TrustOps:

| What LangGraph does                                                                                             | What it does **not** do                                            |
| --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Orders deterministic harness nodes (`load_posture`, `load_evidence_gaps`, `propose_actions`, SOC `load_alerts`) | Call LangChain chat models or own compliance truth                 |
| Optional `MemorySaver` checkpoints when `--checkpoint-thread` is set                                            | Replace RBAC, redaction, evaluation, or approvals                  |
| Same node functions as the sequential runner                                                                    | Persist checkpoints across server restarts (in-process only today) |

**No LangChain dependency.** TrustOps uses the optional `langgraph` extra only.
Models run through `model_client.py` (urllib / boto3 / vertex / cortex) **after**
the graph finishes — never inside graph nodes.

**No durable checkpoints yet** beyond in-memory `MemorySaver` keyed by
`--checkpoint-thread` (or API `idempotency_key` when `orchestrator=langgraph`).
Use this for long SOC reviews that may retry mid-graph; production resume across
restarts needs a pluggable checkpointer (future).

Both harnesses accept `--orchestrator langgraph`:

```bash
security-lakehouse agents posture-review --lake ./lake --orchestrator langgraph
security-lakehouse agents soc-triage --lake ./lake --orchestrator langgraph \
  --checkpoint-thread soc-review-2026-07-03 --resume
```

Posture review skips `propose_actions` when evidence gaps are empty (graph routes
to `finalize_no_gaps` instead of emitting spurious requests).

Do **not** add `langchain` as a direct dependency unless a future integration
requires LangChain-specific adapters. Prefer TrustOps `model_client` and typed
tool contracts.

No model is required. If no provider is configured, the harness runs in
`rules_only` mode.

Environment knobs:

| Variable                         | Purpose                                                                                                     |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `TRUSTOPS_AGENT_PROVIDER`        | `rules_only`, `ollama`, `openai`, `openai_compatible`, `anthropic`, `bedrock`, `vertex`, `snowflake_cortex` |
| `TRUSTOPS_AGENT_MODEL`           | Provider model name                                                                                         |
| `TRUSTOPS_AGENT_BASE_URL`        | Local provider URL, defaulting to Ollama at `http://127.0.0.1:11434` when provider is `ollama`              |
| `TRUSTOPS_AGENT_API_KEY_ENV`     | Name of the environment variable holding the provider API key (API-key providers only)                      |
| `TRUSTOPS_AGENT_REGION`          | Bedrock AWS region (falls back to `AWS_REGION`)                                                             |
| `TRUSTOPS_AGENT_PROJECT`         | Vertex AI GCP project id                                                                                    |
| `TRUSTOPS_AGENT_LOCATION`        | Vertex AI location (defaults to `us-central1`)                                                              |
| `TRUSTOPS_AGENT_USE_MODEL`       | Set to `1` to actually call the provider; unset means deterministic harness only                            |
| `TRUSTOPS_AGENT_TIMEOUT_SECONDS` | Optional provider request timeout, clamped between 1 and 120 seconds                                        |

`openai_compatible` is supported for local or customer-chosen providers that
serve `/chat/completions`. The harness records provider metadata but never
prints raw API keys.

### Bring-your-own cloud model

Three providers authenticate through an ambient credential chain instead of an
API key, so no model secret is ever held by TrustOps:

- **`bedrock`** — Amazon Bedrock via the model-agnostic Converse API.
  Credentials come from the standard AWS chain (IAM role / IRSA / env); set
  `TRUSTOPS_AGENT_REGION` (or `AWS_REGION`) and a Bedrock `TRUSTOPS_AGENT_MODEL`.
  Requires the `aws` extra (`boto3`).
- **`vertex`** — Vertex AI `generateContent` with an Application Default
  Credentials bearer token. Set `TRUSTOPS_AGENT_PROJECT` and a Gemini
  `TRUSTOPS_AGENT_MODEL`. Requires `google-auth`.
- **`snowflake_cortex`** — inference runs **inside** Snowflake via
  `SNOWFLAKE.CORTEX.COMPLETE`, reusing the same key-pair connection as the
  medallion sink (`SNOWFLAKE_ACCOUNT`, `SNOWFLAKE_USER`,
  `SNOWFLAKE_PRIVATE_KEY_FILE`). The redacted prompt is the only thing that
  crosses into the warehouse, so evidence never leaves the customer's lake to
  reach a third-party model endpoint.

## Budget policy

Model use is budgeted by the harness, not by prompt wording. Defaults are small
enough for local models and CI:

| Variable                           | Default | Purpose                                                               |
| ---------------------------------- | ------- | --------------------------------------------------------------------- |
| `TRUSTOPS_AGENT_MAX_CONTEXT_CHARS` | 12000   | Maximum serialized context sent to a model after compaction           |
| `TRUSTOPS_AGENT_MAX_FACT_ITEMS`    | 20      | Maximum evidence gaps, alerts, and deterministic decisions in context |
| `TRUSTOPS_AGENT_MAX_OUTPUT_TOKENS` | 600     | Maximum provider output tokens requested                              |
| `TRUSTOPS_AGENT_MAX_STRING_CHARS`  | 1000    | Maximum individual string length before deterministic truncation      |

The CLI also accepts per-run overrides:

```bash
security-lakehouse agents soc-triage \
  --lake ./lake \
  --provider ollama \
  --model llama3.1 \
  --max-fact-items 10 \
  --max-context-chars 8000 \
  --max-output-tokens 300
```

Every model context includes a `budget` object with estimated context size,
estimated tokens, applied item limits, omitted counts, and `status`. If context
still exceeds budget after deterministic compaction, the harness records
`model_skipped: context_budget_exceeded`, stays in `rules_only` mode, and does
not call the provider.

## Evaluation and confidence

Every harness run returns an `evaluation` object:

```json
{
  "ok": true,
  "score": 100,
  "confidence": "high",
  "risk_level": "low",
  "checks": [],
  "failures": [],
  "coverage": {}
}
```

Confidence is computed by TrustOps, not by the model. The harness scores
allowed actions, approval gating, rejected tool-call tracking, context-budget
enforcement, and use-case coverage such as evidence-gap or high-priority alert
coverage. If a model returns its own confidence field, TrustOps ignores it.

Rejected model tool calls are treated as useful safety telemetry. They do not
execute and do not make the run unsafe by themselves, but they lower deterministic
confidence to `medium` because the model attempted something outside the
approved contract.

## First workflow

`run_posture_review(...)`:

1. loads current posture
2. applies role redaction
3. loads missing/stale/expired evidence gaps
4. proposes evidence-request actions
5. marks every write as `requires_approval`

This is intentionally deterministic. LangGraph can orchestrate the same nodes
with `--orchestrator langgraph`, and later model-backed nodes can summarize or
prioritize, but they must consume the already-redacted state and act only
through TrustOps APIs.

```bash
security-lakehouse agents posture-review \
  --lake ./lake \
  --role read_only \
  --orchestrator langgraph
```

That command changes orchestration, not authority. Evidence, redaction,
control results, proposed writes, approvals, and evaluation still come from
TrustOps deterministic code.

With `TRUSTOPS_AGENT_USE_MODEL=1`, the optional provider receives:

- the objective
- role-redacted posture
- role-redacted evidence gaps
- deterministic action proposals
- an allowed tool manifest
- a strict JSON output schema

The model may return summaries, priority ordering, and proposed tool calls.
TrustOps validates tool names and keeps every write as `requires_approval`.
The model cannot mark a control passing, mutate evidence, bypass RBAC, or
execute writes.

## Use-case harnesses

The harness pattern is use-case oriented. Each harness must run without a
model, expose only approved tool proposals, and carry deterministic evaluation
results.

| Harness        | Deterministic inputs                                               | Model role                                                 | Guardrail evaluation                                                                |
| -------------- | ------------------------------------------------------------------ | ---------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Posture review | current posture, evidence gaps, role redaction                     | summarize and rank evidence requests                       | proposed writes require approval and stay in the allowed tool set                   |
| SOC triage     | open detection, vulnerability, runtime, cloud, and identity alerts | summarize, rank, and propose case/enrichment/owner actions | high/critical open alerts must have proposed actions; all writes are approval-gated |

Run the SOC harness locally:

```bash
security-lakehouse agents soc-triage --lake ./lake --role read_only --orchestrator langgraph
```

Configuring a provider still does not call a model unless `--use-model` or
`TRUSTOPS_AGENT_USE_MODEL=1` is set:

```bash
security-lakehouse agents soc-triage \
  --lake ./lake \
  --provider ollama \
  --model llama3.1
```

## Self-hosted run modes

Teams can run the harness without changing the compliance engine:

| Mode           | How it runs                                                                              | Use when                       |
| -------------- | ---------------------------------------------------------------------------------------- | ------------------------------ |
| CLI            | `security-lakehouse agents posture-review --lake <lake>`                                 | local audits, CI checks, demos |
| Scheduler      | cron, Kubernetes `CronJob`, or the TrustOps scheduler                                    | recurring evidence-gap review  |
| Service worker | internal worker calls `/api/v1/*` and writes proposed actions back through TrustOps APIs | production agent operations    |
| UI/API trigger | console button or headless API starts a saved workflow                                   | human-in-the-loop review       |

Self-hosted deployments keep the same boundaries: tenant-scoped lake path,
server-side RBAC, redacted reads, append-only audit events, and approval before
agent-proposed writes. LangGraph is useful for branching, retries, multi-agent
review, and long-running state, but it is not the source of compliance truth.

## Persisted run contract

Server mode persists harness runs in the application-state database:

```bash
curl -s -X POST "$TRUSTOPS_URL/api/v1/agent-runs" \
  -H "authorization: Bearer $TRUSTOPS_API_KEY" \
  -H "content-type: application/json" \
  --data '{"harness":"posture_review","orchestrator":"langgraph","idempotency_key":"review-2026-06-22"}' | jq .
```

The response includes the run mode, orchestrator, deterministic evaluation,
proposed actions, budget/provider metadata, data-readiness preflight, and the
sanitized run state. The raw lake path is not persisted in the state payload.
Supplying the same tenant-scoped `idempotency_key` returns the previous run
instead of rerunning the harness, which makes scheduler and agent retries safe.

Approval and rejection require an independent reviewer authenticated through OIDC
or SAML, with write scope. The run creator and API-key sessions cannot approve
their own proposals. Submit the decision through the signed-in console session
or its authenticated API session:

```bash
curl -s -X POST "$TRUSTOPS_URL/api/v1/agent-runs/$RUN_ID/decisions/0/approve" \
  --cookie "$TRUSTOPS_SESSION_COOKIE" \
  -H "content-type: application/json" \
  --data '{"note":"approved for audit prep"}' | jq .
```

Approval is idempotent. Retrying an already executed decision returns the stored
execution result instead of creating another task, evidence request, or snapshot.
An execution error rolls back uncommitted database writes and records the decision
as terminal `failed`, preserving its original approval. Other proposals in the run
remain usable. Failure metadata uses a fixed code, not raw exception text.
A failed decision cannot be approved again: inspect any external or file effects
and create a new reviewed run if another action is needed.

A terminated worker can leave an `executing` claim. After inspecting the action's
records, an independent SSO reviewer can close that claim with a nonempty reason:

```bash
curl -s -X POST "$TRUSTOPS_URL/api/v1/agent-runs/$RUN_ID/decisions/0/reconcile" \
  --cookie "$TRUSTOPS_SESSION_COOKIE" \
  -H "content-type: application/json" \
  --data '{"reason":"Worker terminated; reviewed task and snapshot records"}' | jq .
```

Reconciliation records `failed` with `failure_code: outcome_unknown`, the reviewer,
and the reason. It never executes, retries, or asserts that a previous side effect
did not happen. A live worker holds a per-run lock, so recovery returns 409 until
that worker exits. PostgreSQL coordinates this lock across hosts through the
database; SQLite coordinates processes using a lock beside its database file.
Keep all server workers on the same upgraded code before recovering old claims.

MCP clients can call the same persisted-run contract when pointed at a deployed
TrustOps API:

```bash
export TRUSTOPS_API_URL="https://trustops.example.com"
export TRUSTOPS_API_KEY="..."
trustops-mcp
```

The MCP tools `list_agent_runs`, `create_agent_run`, `get_agent_run`,
`approve_agent_decision`, and `reject_agent_decision` call `/api/v1/agent-runs*` over the authenticated API.
They do not bypass RBAC, tenant isolation, data-readiness preflight,
idempotency, approval state, or audit logging.

Currently executable proposal actions:

- `create_evidence_request`
- `create_remediation_task`
- `create_soc_case` as an internal remediation task
- `assign_owner` as an internal remediation task
- `freeze_snapshot` when the caller also has `snapshot` scope

External actions such as webhook, Slack, ticketing, and enrichment calls are not
executed by agent approval. They must go through the workflow engine and egress
guardrails.

Supported harness values:

- `posture_review`
- `soc_triage`

Creating a run requires write scope. The run reads with the caller's own role
unless a more restrictive role is requested. API requests cannot provide raw
model keys; optional model use reads only the server's configured provider
environment and still records proposed actions for approval instead of
executing writes.

Every run starts by deciding whether the account already has usable lake data:

- `lake_ready`: use existing normalized/security lake facts
- `partial_lake`: run targeted ingestion or control evaluation first
- `needs_ingestion`: configure read-only connectors or load existing exports

This is a deterministic preflight, not an LLM decision. The persisted run
includes required artifacts, per-artifact row counts, relative artifact paths,
and recommended next-step commands using placeholders such as `<lake>` and
`<connector_id>`. Absolute local lake paths are not persisted in the agent
state, so UI, scheduler, MCP, and headless clients can show the guidance
without exposing machine-specific paths.

## Non-negotiables

Agents do not own:

- RBAC
- tenant isolation
- evidence freshness
- control pass/fail evaluation
- redaction policy
- idempotency
- snapshot hashes
- audit truth

Those stay in TrustOps core and tests.
