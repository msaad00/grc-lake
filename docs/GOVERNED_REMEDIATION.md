# Governed exceptions and remediation

A risk exception records a time-limited acceptance decision. It never changes a
control result to `pass` or supplies missing evidence.

## Exception lifecycle

A control manager requests an exception with a reason and a future, timezone-aware
expiry. The server binds the requester to the authenticated user. The request is
`pending` until a different control manager approves it. Approval binds the
reviewer identity and time on the server; caller-supplied approver names are
rejected. Expired or revoked requests cannot be approved. The active list applies
these checks before pagination.

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
task retains its verification history. A failed verification leaves it open and
rolls back the submitted note. Unlinked administrative tasks still support manual
closure; this is not an assurance conclusion.

The receipt is a point-in-time retest over observed assets. It does not establish
complete inventory coverage, sustained operating effectiveness, or remediation of
assets absent from the generation. A resolution note or external link is context,
not proof of a passing retest. The console displays this distinction and keeps the
note available when verification fails.
