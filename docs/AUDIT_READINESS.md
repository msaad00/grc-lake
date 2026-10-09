# Audit Readiness (Headless-First)

TrustOps audit readiness is exposed through **`GET /api/v1/platform/audit-readiness`**
for headless consumers (CI, agents, runbooks) and the **`/console/audit-room/`**
console for human GRC leads and auditors. Both surfaces read the same payload.

See [HEADLESS_GRC.md](HEADLESS_GRC.md) for the overall architecture.

## Executive summary

| Dimension                     | TrustOps v0.2.x                                            |
| ----------------------------- | ---------------------------------------------------------- |
| Continuous control monitoring | Deterministic tests over customer lake                     |
| Framework packs               | SOC 2, NIST AI RMF, FedRAMP foundation, CIS AWS, ISO packs |
| Evidence automation           | Open connector catalog + read-only cloud posture           |
| Auditor experience            | Trust-center shares + `auditor` role redaction             |
| Access reviews                | Access-review campaigns with certify/revoke/flag           |
| Policy management             | Template library + employee acknowledgment on publish      |
| Point-in-time audit           | Assessment snapshots + hash chain                          |
| Personnel / HRIS              | BambooHR, Rippling, Workday connectors + offboarding check |
| Vendor risk                   | MVP vendor risk module + audit-room diligence rollups      |
| Workflow automation           | Native workflow canvas with approvals                      |
| Self-host / data residency    | **Yes**                                                    |
| Headless / agent API          | **Yes** — MCP, OpenAPI, agent harness, CI gates            |

## Workflow checklist

### Implemented workflows

1. **Connect sources** — AWS/Azure/GCP/Snowflake/GitHub/Okta connectors with probe + sync health
2. **Map frameworks** — Register packs; dashboard framework readiness bars
3. **Run control tests** — Gold `control_tests.jsonl`; pass/fail on dashboard and controls pages
4. **Track violations** — Open findings with severity, owner guidance, remediation tasks
5. **Request evidence** — Evidence-request workflow tied to controls
6. **Access reviews** — Periodic certification campaigns (SOC 2 CC6.x pattern)
7. **Policies** — Adopt/publish from bundled templates
8. **Auditor sharing** — Scoped trust-center tokens with expiry and revocation
9. **Point-in-time** — Write assessment snapshot; ledger chain for drift detection
10. **Audit log** — Request audit trail for API and console actions
11. **Headless gates** — API keys, correlation IDs, idempotency for CI and agents

### Known gaps

| Gap                    | Workaround today                               |
| ---------------------- | ---------------------------------------------- |
| Auditor marketplace    | Export trust share + PDF snapshot              |
| Pen test coordination  | External process                               |
| Device/agent inventory | Connector evidence only                        |
| Native billing/signup  | [Commercial hosted mode](COMMERCIAL_HOSTED.md) |

## Audit score formula

The audit-readiness API computes:

```text
audit_score = (
  0.4 × posture score
+ 0.3 × control test pass rate
+ 0.2 × framework readiness rate
) / 0.9
```

A framework counts as ready only when its score is ≥ 85 **and** at least 50% of
its catalog controls have been assessed. Each framework's `assessed_controls`,
`total_controls`, and `coverage_pct` are returned under `frameworks`.

The score reflects only the organization's own evidence, control tests, and
frameworks. `workflow_coverage` lists product capabilities for reference; it is
marked `scored: false` and never contributes to the score.

State:

- `audit_ready` — score ≥ 85 and no blocking gaps
- `on_track` — score ≥ 60
- `needs_work` — otherwise

Blocking gaps include: no connectors and no evidence from any source, failing controls, open evidence requests, no active access review, no auditor share, overdue or missing vendor diligence, unattested published policies.

## Exports and continuous eval

| Output           | Route / surface                                  | Notes                                             |
| ---------------- | ------------------------------------------------ | ------------------------------------------------- |
| Executive PDF    | `GET /api/v1/snapshots/{snapshot_id}/export.pdf` | Point-in-time board/vendor package (`read` scope) |
| Activity stream  | `GET /api/v1/audit-log`                          | SIEM and compliance archive export                |
| Live posture SSE | `GET /api/v1/stream`                             | Continuous-eval stream for dashboards             |
| Ingestion health | `GET /api/v1/ingestion/status`                   | Schedules, scale tier, connector freshness        |

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8787/api/v1/snapshots/<snapshot_id>/export.pdf" \
  -H 'accept: application/pdf' -o audit-snapshot.pdf
```

CLI snapshot creation (PDF requires the snapshot id from the API response or `list_snapshots`):

```bash
security-lakehouse assessment snapshot --lake build/lakehouse --reason vendor_due_diligence
```

## Related

- [HEADLESS_GRC.md](HEADLESS_GRC.md)
- [RELEASE_READINESS.md](RELEASE_READINESS.md)
- [DEPLOYMENT.md](DEPLOYMENT.md)
