# Governed exceptions and remediation

A risk exception records a time-limited acceptance decision. It never changes a
control result to `pass` or supplies missing evidence.

## Exception lifecycle

A control manager requests an exception with a reason and a future, timezone-aware
expiry. The server binds the requester to the authenticated user. The request is
`pending` until a different control manager approves it. Approval binds the
reviewer identity and time on the server; caller-supplied approver names are
rejected. Expired or revoked requests cannot be approved. The active list applies
these checks before pagination. Expired requests display an expired status even
when no background job has updated their stored lifecycle state.

After upgrading, legacy active exceptions become pending. Their historical
claimed approver remains visible, but is not an authenticated approval. Revoke and
re-request those exceptions to establish the independent review trail.

## Verified remediation

A task linked to a control or finding cannot be resolved by changing its status.
Use `POST /api/v1/remediation/tasks/{id}/verify` as a control manager, with an
optional `resolution_note`. The task needs a control ID. Verification requires:

- an intact sealed generation owned by the authenticated tenant;
- passing control tests with fresh required evidence;
- observations and collection times after task creation and no later than the
  verification time.

Successful verification appends a receipt containing the authenticated reviewer,
control, generation digest, assessment hash, and raw evidence hashes. Reopening a
task retains its verification history. A conditional database update rejects a
concurrent stale retest instead of overwriting another reviewer's receipt. A failed verification leaves it open and
rolls back the submitted note. Unlinked administrative tasks still support manual
closure; this is not an assurance conclusion.

The receipt is a point-in-time retest over observed assets. It does not establish
complete inventory coverage, sustained operating effectiveness, or remediation of
assets absent from the generation. A resolution note or external link is context,
not proof of a passing retest. The console displays this distinction and keeps the
note available when verification fails.

## Recovering interrupted scheduler history

The daemon logs a sanitized tick failure and tries again on its normal cadence.
Corrupt history stays blocked until reconciled; it is never silently ignored.
CronJobs use `restartPolicy: Never` and `backoffLimit: 0`, leaving the next scheduled
job as the retry boundary.

For an unterminated final line in one tenant's `scheduler_state.jsonl` or
`connector_runs.jsonl`, run:

```bash
security-lakehouse scheduler repair-history --lake /path/to/tenant-lake
```

This explicit recovery takes scheduler and connector-history locks, preserves
original bytes in the owner-only `gold/recovery` directory, and repairs only the
final unterminated record. Interior or newline-terminated corrupt records require
operator reconciliation. Evidence generations and assessment ledgers are outside
this command's scope. A recovery marker blocks ticks if the command is interrupted;
rerunning the command completes recovery. Every configured target waits a full
schedule interval after recovery because the interrupted attempt's execution
cannot be inferred from a torn record. Review the archived tail before retrying
any external action manually.

Reopening retains previous receipts but requires a new generation with evidence
observed after the task's latest update. Partial source collection blocks a
retest. Publishing a failing control assessment reopens resolved tasks owned by
that generation's platform tenant when the application database is available.
Fixture generations can be assigned with `fixtures load --tenant-id <platform-tenant-id>`;
source account IDs remain distinct from platform ownership.
