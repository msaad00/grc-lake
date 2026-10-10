# Webhooks

The `/api/v1` contract is otherwise pull-only: a SIEM, ticketing system, or
runbook has to poll for new findings or a completed assessment. Webhooks push
instead — register an endpoint once and GRC Lake calls it the moment one of a
small set of events happens, signed so the receiver can verify it actually
came from this GRC Lake instance.

This is server mode only (subscriptions live in the application-state
database alongside tenants, users, and the rest of GRC operational state —
see `docs/DATA_MODEL.md`'s physical tables and `src/security_lakehouse/db/models.py`).
Local mode (the zero-dependency stdlib server) has no tenant/DB context to
dispatch webhooks with and does not deliver them.

## Event types

| Event                  | Fires when                                                                                                                                                             |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `assessment.completed` | A point-in-time snapshot is written (`POST /api/v1/snapshots`, a scheduled workflow, or an approved agent decision that freezes one).                                  |
| `finding.created`      | A violation present in a new snapshot was not present in the immediately prior snapshot — a real open/failed/blocked control result that is new since the last freeze. |
| `control.failed`       | A control had zero open violations in the prior snapshot and at least one in the new one — a detected pass→fail transition.                                            |

**How the transition is detected.** GRC Lake snapshots are hash-chained
point-in-time exports (`docs/ARCHITECTURE.md`, `assessment.py`). Each snapshot
already carries its full list of currently-open violations. On every new
snapshot write, the engine diffs that list against the immediately prior
snapshot's violation list (by `violation_id`, and by `control_id` for the
control-level transition) — no separate state machine, just the same
chain-linked data the snapshot already produces. This means:

- These events fire **only on a snapshot write**, not continuously as evidence
  streams in. If nothing calls `POST /api/v1/snapshots` (directly, via a
  scheduled workflow's `action.snapshot`, or via an approved
  `freeze_snapshot` agent decision), no `finding.created`/`control.failed`
  event fires, even if new evidence landed — take a snapshot on the cadence
  you want notified on (a scheduled workflow is the usual answer).
- The very first snapshot of a lake has no prior snapshot to diff against, so
  it only fires `assessment.completed` — every violation in a bootstrap
  import is the starting state, not a "new finding."
- A control that is already failing does not re-fire `control.failed` on
  every subsequent violation against it — only the pass→fail transition does.
  It will, however, still produce a `finding.created` for each new violation.
- A snapshot written by resuming a paused workflow run (`retry_workflow_run`/
  `approve_workflow_run` after a `gate.approval` node) does not dispatch
  webhook events yet, even if that run's DAG includes an `action.snapshot`
  node — only a run started fresh (`run_workflow`, including a scheduler-fired
  one) is wired today. This is a narrower, known gap, not a silent one.

## Registering a subscription

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8787/api/v1/webhooks \
  -H 'content-type: application/json' \
  --data '{
    "url": "https://siem.example.com/ingest/grc-lake",
    "event_types": ["assessment.completed", "finding.created", "control.failed"],
    "description": "SOC SIEM ingest"
  }' | jq .
```

Registering or changing a subscription (`POST`/`PATCH`/`DELETE
/api/v1/webhooks*`) requires the `connector_manage` scope (`admin` /
`security_admin`) — the same scope as configuring an inbound connector,
because a webhook is an outbound integration carrying a signing secret and a
destination for compliance events. Reading the list or a single subscription
only requires `read`, and never includes the secret.

`secret` is optional on create; when omitted, GRC Lake generates one. Either
way it is returned **in full exactly once**, in the create response — store it
now. Every later `GET`/list omits it.

| Method   | Path                               | Scope              | Purpose                                    |
| -------- | ---------------------------------- | ------------------ | ------------------------------------------ |
| `GET`    | `/api/v1/webhooks`                 | `read`             | List subscriptions (secret omitted)        |
| `POST`   | `/api/v1/webhooks`                 | `connector_manage` | Register a subscription; secret shown once |
| `GET`    | `/api/v1/webhooks/{id}`            | `read`             | Get one subscription (secret omitted)      |
| `PATCH`  | `/api/v1/webhooks/{id}`            | `connector_manage` | Update url/secret/event_types/enabled      |
| `DELETE` | `/api/v1/webhooks/{id}`            | `connector_manage` | Remove a subscription                      |
| `GET`    | `/api/v1/webhooks/{id}/deliveries` | `read`             | Delivery attempt history (audit trail)     |

## Payload shape

Every delivery is a POST with this envelope:

```json
{
  "event": "finding.created",
  "event_id": "a5e6c9c2-...-uuid",
  "occurred_at": "2026-09-22T14:03:11+00:00",
  "tenant_id": "b1e2...-uuid",
  "data": { "...": "event-specific, see below" }
}
```

`event_id` is a fresh UUID per delivery attempt series (stable across
retries of the same attempt) — use it as the idempotency key on the receiving
side if your endpoint might see a retried delivery twice.

<details>
<summary><code>assessment.completed</code> <code>data</code></summary>

```json
{
  "snapshot_id": "assessment-20260922T140311Z-a1b2c3d4e5f6",
  "assessment_hash": "…sha256…",
  "prev_hash": "…sha256 or null…",
  "snapshot_reason": "api_request",
  "evaluated_at": "2026-09-22T14:03:11+00:00",
  "posture_score": 87.5,
  "posture_state": "attention_required",
  "open_violation_count": 4,
  "critical_violation_count": 1,
  "high_violation_count": 1
}
```

Fetch the full snapshot with `GET /api/v1/snapshots/{snapshot_id}` if you need
more than this summary.
</details>

<details>
<summary><code>finding.created</code> <code>data</code></summary>

```json
{
  "snapshot_id": "assessment-20260922T140311Z-a1b2c3d4e5f6",
  "violation_id": "SOC2-CC6.1:evt-001",
  "control_id": "SOC2-CC6.1",
  "event_id": "evt-001",
  "asset_id": "aws:iam:role/admin",
  "severity": "high",
  "state": "open",
  "source": "okta",
  "event_type": "identity.access_review",
  "detected_at": "2026-09-22T13:01:00Z",
  "evidence_ref": "s3://evidence/evt-001.json"
}
```

</details>

<details>
<summary><code>control.failed</code> <code>data</code></summary>

```json
{
  "snapshot_id": "assessment-20260922T140311Z-a1b2c3d4e5f6",
  "control_id": "SOC2-CC6.1",
  "evaluated_at": "2026-09-22T14:03:11+00:00"
}
```

</details>

## Signature verification

Every delivery carries:

| Header                           | Value                                                                 |
| -------------------------------- | --------------------------------------------------------------------- |
| `X-GRC-Lake-Signature`           | `sha256=<hex hmac-sha256 of the raw request body>`                    |
| `X-GRC-Lake-Timestamp`           | Unix seconds when this attempt was sent                               |
| `X-GRC-Lake-Timestamp-Signature` | `sha256=<hex hmac-sha256 of "<timestamp>." followed by the raw body>` |
| `X-GRC-Lake-Event`               | the event type, e.g. `finding.created`                                |
| `X-GRC-Lake-Delivery`            | the delivery's `event_id`                                             |

`X-GRC-Lake-Signature` covers the body only. The body contains `event_id` and
the event's `occurred_at`, but no send time, so a captured delivery verifies
again if replayed later. Receivers should:

- verify `X-GRC-Lake-Timestamp-Signature` and reject a timestamp more than five
  minutes from their clock (each retry carries a fresh timestamp); and
- de-duplicate on `event_id` for at least that window, because a retry after a
  lost response legitimately repeats the same body.

The `X-TrustOps-*` signature, event, and delivery headers are still sent with
the same values for receivers built before the rename.

Recompute the HMAC over the **raw bytes** of the body (before any JSON
re-parsing/re-serialization, which can reorder keys or change whitespace) and
compare with a constant-time equality check:

```python
import hashlib
import hmac

import time

TOLERANCE_SECONDS = 300


def verify_grc_lake_webhook(secret: str, raw_body: bytes, timestamp: str, signature_header: str) -> bool:
    """Check X-GRC-Lake-Timestamp-Signature and reject stale deliveries."""
    algo, _, digest = signature_header.partition("=")
    if algo != "sha256" or not timestamp.isdigit():
        return False
    if abs(time.time() - int(timestamp)) > TOLERANCE_SECONDS:
        return False
    signed = timestamp.encode("ascii") + b"." + raw_body
    expected = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, digest)
```

```javascript
// Node.js
const crypto = require("crypto");

const TOLERANCE_SECONDS = 300;

function verifyGrcLakeWebhook(secret, rawBody, timestamp, signatureHeader) {
  const [algo, digest] = signatureHeader.split("=");
  if (algo !== "sha256" || !/^[0-9]+$/.test(timestamp)) return false;
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > TOLERANCE_SECONDS)
    return false;
  const expected = crypto
    .createHmac("sha256", secret)
    .update(Buffer.concat([Buffer.from(`${timestamp}.`), rawBody]))
    .digest("hex");
  if (!digest || digest.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(digest));
}
```

## Delivery, retry, and failure behavior

- Outbound requests go through the same SSRF guard every other egress path in
  this codebase uses (`security_lakehouse/netguard.py`): only `http`/`https`,
  and the _resolved_ address must be public — a registered URL that resolves
  to a private/loopback/link-local address is refused before any request is
  attempted, including on a redirect hop.
- **Optional destination allowlist.** Set `GRC_LAKE_WEBHOOK_EGRESS_ALLOWLIST`
  (comma-separated `host` or `host:port` entries) to additionally restrict
  webhook deliveries to specific approved destinations — e.g. a SIEM vendor's
  fixed IP/hostname. Unset (the default) means "any public address" is
  allowed, same as before this variable existed: a webhook subscription is a
  tenant registering _its own_ receiving endpoint for _its own_ events (the
  GitHub/Stripe self-service webhook model), not an admin-authored automation
  target, so this is deliberately **not** deny-by-default the way the
  workflow engine's `GRC_LAKE_WORKFLOW_EGRESS_ALLOWLIST` is (see "Relationship
  to `action.webhook`" below) — turning that one on does not, and should not,
  make every tenant's webhook subscription stop delivering.
- One retry on failure (non-2xx response, timeout, or connection error) with a
  short backoff — two attempts total by default. A 2xx on either attempt is a
  success; a non-2xx or network error on the last attempt is a recorded
  failure.
- **Delivery is synchronous with the write that triggered it, not queued.**
  This codebase has no existing background job/worker system to build on for
  this slice (see `scheduler.py`'s docstring — it runs on a poll/tick model,
  not a push queue), so delivery runs inline, off the request's async event
  loop, right after the snapshot's hash-chain lock is released. A dead or slow
  receiver never blocks or fails the snapshot/finding write itself — the
  write already succeeded before delivery is attempted — but a burst of many
  simultaneously-transitioning controls will serialize their deliveries one
  after another. A future PR moving this onto a real queue (so delivery is
  decoupled from the request entirely) is a reasonable next step if delivery
  volume grows; in the meantime, one snapshot write dispatches at most 200
  `finding.created` and 200 `control.failed` events (independently), and
  fanning one event out to subscribers is separately capped at 200
  subscriptions — the remainder in either case is logged and skipped rather
  than silently dropped, and `assessment.completed` always fires regardless.
- Every delivery attempt's final outcome (success/failed, attempt count, HTTP
  status, error) is recorded and visible at
  `GET /api/v1/webhooks/{id}/deliveries` — this is the audit trail for "did
  the SIEM actually get notified."

## Relationship to `action.webhook` (workflows)

GRC Lake already has an _outbound_ webhook primitive inside the workflow
engine — `action.webhook`, a DAG node an operator wires up explicitly to POST
to an allowlisted URL as one step of a workflow (see the "Action library"
section of `workflows.py`). That is a different mechanism: it is one-shot,
operator-authored, and gated by `GRC_LAKE_WORKFLOW_EGRESS_ALLOWLIST`. The
subscriptions on this page are the opposite direction of the same idea —
event-driven, receiver-registered, and always-on for whichever event types the
subscriber picked — closer to a GitHub/Stripe webhook than a workflow step.

The legacy `X-TrustOps-Signature`, `X-TrustOps-Event` and `X-TrustOps-Delivery` headers are also sent with identical values for existing receivers.
