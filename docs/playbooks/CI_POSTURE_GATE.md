# CI posture gate playbook

Block merges and deployments when TrustOps posture regresses. Platform engineers should
wire this **before** the human console — same `/api/v1` routes agents and MCP use.

Start with [CI gate](../CI_GATE.md) for the inputs, outputs, and a sample-data demo.

Related: [AGENT_SKILLS.md](../api/AGENT_SKILLS.md) (`ci.gate`) ·
[AGENT_API.md](../api/AGENT_API.md) ·
[HEADLESS_GRC.md](../HEADLESS_GRC.md)

## What the gate checks

| Signal                 | Source                                            | Default threshold                         |
| ---------------------- | ------------------------------------------------- | ----------------------------------------- |
| Posture score          | `GET /api/v1/posture/current`                     | `min-score: 0`                            |
| Critical violations    | posture summary                                   | `max-critical-violations: 0`              |
| Open violations        | posture summary                                   | skipped (`max-open-violations: -1`)       |
| **Control regression** | posture + `GET /api/v1/control-tests?result=fail` | **`max-failing-control-tests: 0`**        |
| Stale evidence         | posture freshness                                 | off unless `fail-on-stale-evidence: true` |

Every request sends **`X-Correlation-ID`** so CI runs appear in the audit trail.

## GitHub Actions (recommended)

Copy [examples/github-actions/trustops-posture-gate.yml](../../examples/github-actions/trustops-posture-gate.yml)
into `.github/workflows/` and set repository secrets:

| Secret               | Value                                              |
| -------------------- | -------------------------------------------------- |
| `TRUSTOPS_URL`       | `https://trustops.example.com` (no trailing slash) |
| `TRUSTOPS_API_TOKEN` | Read-scoped API key (`tops_…`)                     |

Example step:

```yaml
- name: TrustOps posture gate
  uses: msaad00/trustops-security-data-lake/.github/actions/posture-gate@v0.2.22
  with:
    trustops-url: ${{ secrets.TRUSTOPS_URL }}
    api-token: ${{ secrets.TRUSTOPS_API_TOKEN }}
    correlation-id: pr-${{ github.event.pull_request.number }}-${{ github.run_id }}
    min-score: "70"
    max-critical-violations: "0"
    max-failing-control-tests: "0"
```

### Allow known failing controls

```yaml
max-failing-control-tests: "0"
allowed-failing-controls: "SOC2-CC6.1,NIST-AI-RMF-MAP-1.5"
```

Only controls **not** in the allowlist fail the gate.

## Shell script (GitLab, Jenkins, local)

```bash
export TRUSTOPS_URL="http://127.0.0.1:8787"
export TRUSTOPS_API_TOKEN=""   # empty when --allow-insecure-no-auth
export CORRELATION_ID="local-$(date +%s)"
export MIN_SCORE=70
export MAX_FAILING_CONTROL_TESTS=0

./tools/ci/posture-gate.sh
```

## Local dev server

```bash
make pipeline
uv run security-lakehouse serve --lake build/lakehouse --server --allow-insecure-no-auth --port 8787

TRUSTOPS_URL=http://127.0.0.1:8787 MAX_FAILING_CONTROL_TESTS=0 ./tools/ci/posture-gate.sh
# Expect exit 1 when golden fixture has failing control tests
```

## Optional: snapshot on green deploy

After the gate passes, create a release snapshot with an idempotency key:

```bash
curl -sS -X POST "$TRUSTOPS_URL/api/v1/snapshots" \
  -H "Authorization: Bearer $TRUSTOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Correlation-ID: $CORRELATION_ID" \
  -H "Idempotency-Key: release-${GITHUB_SHA}" \
  -d '{"reason":"ci_posture_gate_pass","actor":"ci-posture-gate"}'
```

Requires a write-scoped API key — keep read-only keys for the gate step itself.

## Least-privilege scopes

| Step              | Scope              |
| ----------------- | ------------------ |
| Posture gate      | `read`             |
| Optional snapshot | `write` or `admin` |

## Troubleshooting

| Symptom                                    | Fix                                                                    |
| ------------------------------------------ | ---------------------------------------------------------------------- |
| `Failed to reach …/posture/current`        | Check URL, TLS, and that `security-lakehouse serve` is running         |
| `failing control tests 1 exceed maximum 0` | Fix regression or add to `allowed-failing-controls` temporarily        |
| 401 with empty token                       | Set `TRUSTOPS_API_TOKEN` or run server with `--allow-insecure-no-auth` |

Tests: `pytest tests/test_posture_gate_action.py -q`
