# Console → `/api/v1` migration plan (#413)

The GRC Lake console historically called legacy `/api/*` handlers in `api_legacy.py`. Headless automation, agents, and MCP use `/api/v1/*` via `api_v1.py`. This document freezes the legacy surface and phases console migration.

## Principles

1. **No new legacy routes** — all new HTTP surfaces land in `api_v1.py` (or domain routers mounted from `server_app.py`).
2. **Envelope parity** — v1 responses use `{ data, meta, errors }`; legacy returns ad-hoc shapes. Console hooks should consume v1 envelopes only after typed client methods exist.
3. **Read paths first** — migrate GET/list surfaces before POST mutations so SSE and React Query caches stay stable.

## Legacy freeze list (`api_legacy.py`)

Do **not** add routes here. Existing legacy paths remain until the checklist below is complete:

| Legacy prefix          | v1 replacement                | Console usage today     |
| ---------------------- | ----------------------------- | ----------------------- |
| `/api/posture/current` | `GET /api/v1/posture/current` | `usePosture`, dashboard |
| `/api/control-tests`   | `GET /api/v1/controls/tests`  | `useControlTests`       |
| `/api/violations`      | `GET /api/v1/violations`      | `useViolations`         |
| `/api/evidence`        | `GET /api/v1/evidence`        | `useEvidence`           |
| `/api/frameworks`      | `GET /api/v1/frameworks`      | `useFrameworks`         |
| `/api/connectors`      | `GET /api/v1/connectors`      | `useConnectors`         |
| `/api/mappings`        | `GET /api/v1/mappings`        | crosswalk               |
| `/api/crosswalk/*`     | `GET /api/v1/crosswalk/*`     | crosswalk page          |
| `/api/snapshots`       | `GET /api/v1/snapshots`       | snapshot modal          |

## Phased client migration checklist

### Phase 1 — Read-only assessment (P1)

- [ ] `client.getPosture` → `/api/v1/posture/current` only (remove legacy fallback)
- [ ] `client.getControlTests` → v1
- [ ] `client.getViolations` → v1
- [ ] `client.getFrameworks` → v1
- [ ] Update `hooks/assessment.ts` query keys after cutover

### Phase 2 — Connectors + ingestion (P1)

- [ ] `client.listConnectors` / runs / probe / sync → v1 connector routes
- [ ] `useIngestionStatus` → already v1 (`/api/v1/ingestion/status`)

### Phase 3 — Mutations (P2)

- [ ] Triage / verify / snapshot POST bodies → v1
- [ ] Connector configure / sync → v1

### Phase 4 — Remove legacy shim (P2)

- [ ] Delete unused handlers from `api_legacy.py`
- [ ] Remove stdlib `server.py` legacy paths where duplicated
- [x] CI: fail if `app/web` imports `/api/` paths outside an allowlist (`tests/test_console_uses_v1.py`)

## Testing

- Keep `tests/test_api_legacy.py` until Phase 4; extend `tests/test_api_v1.py` for each migrated client method.
- Playwright smoke (`app/web/e2e/`) must pass after each phase.

## Related

- #413 (this plan)
- #415 `server_app.py` router split (gov-compliance routes merged in #464)
- `docs/api/AGENT_API.md` — canonical v1 contract for agents
