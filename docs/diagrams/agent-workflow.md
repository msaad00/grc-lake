# Agent Workflow (persisted harness)

```mermaid
sequenceDiagram
  participant Operator as Operator / scheduler
  participant API as /api/v1/agent-runs
  participant Harness as Deterministic harness
  participant Lake as Evidence lake
  participant Model as Optional BYO model
  participant Human as Human approver

  Operator->>API: POST agent-runs (idempotency_key)
  API->>Harness: posture_review or soc_triage
  Harness->>Lake: load redacted posture / alerts / gaps
  Harness->>Harness: propose approval-gated actions
  opt LangGraph orchestrator
    Harness->>Harness: load_posture → load_gaps → propose_actions
  end
  opt TRUSTOPS_AGENT_USE_MODEL=1
    Harness->>Model: redacted context + tool manifest
    Model-->>Harness: summary + validated tool calls (no writes)
  end
  Harness-->>API: evaluation + decisions + input_hash
  Human->>API: POST decisions/{i}/approve
  API->>Lake: audited write (task / evidence request / snapshot)
```

Agents answer from generated lake artifacts and persisted run records. Every claim
should cite posture, control tests, evidence refs, or a stored `input_hash`.

Legacy CLI-only flow (local demos):

```bash
security-lakehouse agents posture-review --lake build/lakehouse --orchestrator langgraph
security-lakehouse agents soc-triage --lake build/lakehouse --orchestrator langgraph
```

See [Agent Harness](../AGENT_HARNESS.md) and [Shareable Demo](../SHAREABLE_DEMO.md).
