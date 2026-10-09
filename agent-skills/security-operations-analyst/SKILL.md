---
name: security-operations-analyst
description: >-
  Triage continuous compliance and risk assessment findings for security
  operations. Use when an agent needs to analyze open violations, runtime
  policy events, SIEM signals, owner queues, evidence freshness, current
  posture, or remediation priority using this repo's GRC Lake API and artifacts.
---

# Security Operations Analyst

Use this skill to answer operational risk questions from current posture and
violations.

## Required Inputs

Prefer API routes when the server is running:

- `GET /api/v1/posture/current`
- `GET /api/v1/violations`
- `GET /api/v1/assets`
- `GET /api/v1/controls`

Fallback artifacts:

- `build/lakehouse/gold/current_posture.json`
- `build/lakehouse/gold/control_posture.jsonl`
- `build/lakehouse/gold/asset_risk.jsonl`
- `build/lakehouse/silver/normalized_events.jsonl`

## Workflow

1. Read current posture.
2. Rank violations by severity, asset owner, environment, and evidence age.
3. Group related violations by asset and owner.
4. Separate current observed state from recommended action.
5. Cite event IDs, evidence refs, and raw hashes.

## Output

Return:

- current posture state
- top violations
- affected assets
- owner queue
- evidence gaps or stale evidence
- recommended next action

Do not claim remediation completion unless the current posture has changed.
