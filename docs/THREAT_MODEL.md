# TrustOps trust boundaries

TrustOps evaluates recorded evidence. A passing result describes the configured
checks over those inputs; it is not proof that a provider supplied truthful or
complete data, a certification, or an audit opinion.

## Assets and authorities

Protect provider credentials, authentication sessions, tenant evidence, review
identities, job receipts, and independently retained history. The server derives
tenant and scopes from authenticated authority. Provider account identifiers in
raw evidence do not select the platform tenant. Local CLI access grants filesystem
authority; it is appropriate only for a trusted operator. Insecure development
mode is a synthetic administrator and is refused in production environments.

OIDC/SAML sessions are required for human review. An API key, worker, or language
model cannot supply that authority. Independent-review checks bind known directory
aliases and recorded implementers; operators must maintain those bindings. An
unregistered external identifier cannot be reliably matched to a person by its
spelling. Do not treat an alias string or display name as identity proof.

## Untrusted inputs and agents

Provider records, imported documents, URLs, ticket text, and tool responses can
contain malicious instructions. MCP advertises that evidence is data, and server
scope checks apply independently of client model behavior. Human-only decisions
are absent from MCP discovery. HTML escaping protects rendered markup; it does
not prevent prompt injection in a language model.

An agent must treat retrieved text as evidence to cite, never as permission to
change its instructions, reveal credentials, or invoke another tool. Give agents
read-only credentials by default and explicitly approve consequential proposals.
TrustOps does not guarantee that every external model or client will follow this
boundary. Test the consuming client's tool policy with hostile evidence before
granting write access.

## Evidence and history

Sealed generations, hashes, predecessor links, and keyed review tips detect
specific modifications relative to retained records. Recovery preserves original
bytes and does not add orphaned snapshots to committed history. Verification
fails on missing committed artifacts, changed bytes, extra generation files, and
unsafe recovery paths.

An attacker controlling both the lake and all local integrity records can remove
history and its local verification material together. Local hashes or another
file in that directory cannot establish what existed before deletion. Retain
[checkpoints](EVIDENCE_RECOVERY.md#independently-retained-checkpoints) and backups
under separate access control or retention-locked storage. Checkpoint creation
and rotation are explicit operator actions; external anchoring is not automatic.
An operator with the application database, signing keys, and filesystem is inside
the trust boundary, not an attacker contained by tenant API authorization.

## Availability and resource costs

Queued work uses tenant fairness, admission limits, separate execution processes,
leases, and execution deadlines. Cancellation or interruption can leave an
external side effect with an unknown outcome; reconcile it before retrying.
Idempotency receipts prevent automatic replay, not distributed exactly-once
execution. Killing a worker cannot roll back a provider API operation.

SSE coalesces a tenant's generation reads and refreshes unchanged-generation
payloads within 60 seconds. Read caches are process-local. Full evaluations retain
complete generations; incremental evaluation still has full-generation write
cost. Schedule and monitor retention, either the explicit commands described in
[continuous ingestion](CONTINUOUS_INGESTION.md) or the opt-in
[automatic retention](OPERATIONS_CONTRACTS.md#automatic-retention). Archived history and retained job
receipts still consume storage. Synthetic tests do not establish production
capacity, latency objectives, or live-provider correctness.

## Deployment responsibilities

Use TLS, restricted network access, least-privilege provider credentials, separate
secret storage, database backups, and independently controlled evidence retention.
Keep operator-only archives inaccessible to tenant users. Validate tenancy,
provider permissions, recovery, and workload limits in the intended deployment.
Report vulnerabilities privately using [the security policy](../SECURITY.md).
