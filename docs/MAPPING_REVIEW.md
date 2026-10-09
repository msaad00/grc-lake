# Mapping review

GRC Lake ships a Common Control Framework: reusable safeguards, each mapped to
the framework requirements it satisfies (see
[Common Control Framework](COMMON_CONTROL_FRAMEWORK.md)). Before an auditor
relies on a mapping, someone has to confirm that the safeguard's evidence
really answers that requirement. This page covers who can do that, what gets
recorded, and how the result shows up in coverage.

## What "reviewed" means

Each mapping in `controls/safeguards.json` ships with a `review_status`:

- **reviewed**: a GRC Lake maintainer confirmed the equivalence against the
  requirement text. The console and API call this **maintainer-reviewed**.
- **proposed**: suggested by a published crosswalk or by matching titles, and
  not yet confirmed by anyone.

Your organization can add its own decision on top of either state:

| Org decision      | Effective state for your tenant                  | In evaluated coverage | Attestable (OSCAL, "reviewed" counts) |
| ----------------- | ------------------------------------------------ | --------------------- | ------------------------------------- |
| none              | maintainer-reviewed or proposed, as shipped      | yes                   | only if maintainer-reviewed           |
| **approve**       | **org-reviewed** (a proposed mapping)            | yes                   | yes                                   |
| **approve**       | stays maintainer-reviewed (already reviewed)     | yes                   | yes                                   |
| **needs changes** | needs changes                                    | yes                   | no                                    |
| **reject**        | rejected, also for a maintainer-reviewed mapping | **no**                | no                                    |

A rejected mapping leaves your tenant's evaluated coverage and is reported as
rejected, so the requirement it covered can fall back to unmapped. Neither kind
of review is a certification.

The state is computed in one place,
`security_lakehouse.safeguards.effective_review_state`, and every surface reads
it: CCF coverage, the framework coverage ledger, the review queue, OSCAL export,
and assessment snapshots.

## Coverage is never blended

Counts keep each kind of confirmation separate:

- **catalogued**: requirements in the catalog
- **mapped**: requirements with at least one mapping that is not rejected
- **maintainer-reviewed**: requirements with at least one maintainer-reviewed mapping
- **org-reviewed**: requirements attestable only through your approvals
- **rejected**: mappings (and requirements left without coverage) your org rejected

`reviewed` / `attestable` equals maintainer-reviewed plus org-reviewed. With no
org decisions every number equals the shipped one.

## Audit trail

Decisions are appended to `<lake>/gold/mapping_reviews.jsonl`. The shipped
`controls/safeguards.json` is never modified. In server mode each tenant has its
own lake, so each tenant has its own log.

Each record holds:

- the mapping (`safeguard_id`, `framework_id`, `control_id`)
- `decision`: `approve`, `reject`, or `needs_changes`
- `rationale` (required)
- `reviewer`, `reviewer_id`, `reviewer_role`, and `auth_method`, taken from
  the signed-in user in server mode
- `decided_at`
- an optional `evidence_ref`
- the mapping's published `source_anchor` at decision time
- `supersedes`: the decision it replaces

The latest decision for a mapping wins, and earlier ones stay in the log. The
log is hash-chained (`prev_hash`, `record_hash`) and serialized across
processes, like the other GRC Lake ledgers. `GET /api/v1/mapping-reviews/summary`
and `frameworks review export` report whether the chain verifies.

### Integrity

- Decisions are applied only from a log that verifies. If the chain is broken
  (an edited record, a torn line after a crash, a missing or wrong tip MAC),
  every mapping falls back to its shipped review state, no new decision can be
  recorded, and each coverage surface says so with `review_log_verified: false`:
  `GET /api/v1/ccf/coverage`, `GET /api/v1/frameworks/coverage` (each framework
  row and the summary), `GET /api/v1/mapping-reviews/summary`, and the snapshot
  `mapping_review.summary`. Restore `gold/mapping_reviews.jsonl` (and its
  `mapping_reviews.tip.json` sidecar) from backup to recover.
- Each decision batch is written with one append and `fsync`, so a batch lands
  whole or, after a crash mid-write, as a torn line that verification reports.
- When `GRC_LAKE_COOKIE_SIGNING_KEY` is set (always, when server auth is on),
  the chain tip is also MACed with a key derived from it and stored in
  `gold/mapping_reviews.tip.json`. Someone who can write the lake but does not
  hold the key cannot rewrite the log and recompute every hash undetected.
  `decision_log.tip_mac` reports `verified`, `missing`, `invalid`, or
  `not_configured` (no key; local mode). Rotating the key makes an existing
  tip MAC report `invalid` until you re-sign it (see
  [Rotating the signing key](#rotating-the-signing-key)).

### Rotating the signing key

After changing `GRC_LAKE_COOKIE_SIGNING_KEY`, re-sign each lake's decision-log
tip with the new key. Run it with the new key in `GRC_LAKE_COOKIE_SIGNING_KEY`
and the old one in any other variable you name:

```bash
export GRC_LAKE_COOKIE_SIGNING_KEY="<new key>"
export GRC_LAKE_PREVIOUS_SIGNING_KEY="<old key>"
grc-lake frameworks review resign --lake <root>/tenants/<tenant_id> \
  --previous-key-env GRC_LAKE_PREVIOUS_SIGNING_KEY --actor ops@example.com
unset GRC_LAKE_PREVIOUS_SIGNING_KEY
```

The command holds the log's lock, verifies the hash chain, and checks the
recorded tip MAC against the old key. Only then does it write a new tip MAC
with the current key. It refuses, and writes nothing, when the chain is broken,
the `mapping_reviews.tip.json` sidecar is missing, or the recorded MAC was not
made with the old key. A log rewritten by someone without the old key can
therefore never be re-signed. Restore that log from backup instead. A tip that
already verifies with the current key is left as is (`status: already_current`).

Each re-sign appends a `tip_resigned` entry (actor, time, log length, tip hash)
to the hash-chained `gold/mapping_review_audit.jsonl`. It appears in the
workbench audit log under **Mapping review**. Neither key is recorded. The
output ends with the `decision_log` verification, which reports
`tip_mac: verified` after a successful re-sign. In a multi-tenant deployment,
run the command once per `tenants/<tenant_id>` lake.

Each assessment snapshot also pins a `mapping_review` block: the counts above
plus the decision-log tip hash. An auditor can then tie a snapshot's coverage to
the exact decisions in force when it was frozen.

## Who can decide

| Principal                                                     | List queue and history | Record a decision |
| ------------------------------------------------------------- | ---------------------- | ----------------- |
| `admin`, signed-in console session                            | yes                    | yes               |
| `compliance_reviewer`, signed-in console session              | yes                    | yes               |
| any other role                                                | yes                    | no (403)          |
| any API key used as a bearer token (agents, CI, scripts, MCP) | yes                    | no (403)          |
| MCP tools                                                     | yes                    | no tool exists    |

The server enforces both checks. `mapping_review` is a separate scope: only
`admin` and the new `compliance_reviewer` role hold it. A decision also needs an
interactive session. A bearer API key is refused whatever its role, so an agent
holding an admin key still cannot approve. The request body has no reviewer
field, and one sent anyway is rejected: the reviewer is always the
authenticated user.

A console session opened with an API key (`/api/v1/auth/session-from-key`)
counts as interactive. The record then carries `auth_method: session:api_key`,
which separates it from SSO sessions (`session:oidc`, `session:saml`).

In local mode (no server login) the CLI records decisions and requires
`--reviewer`. Those records say `auth_method: cli-local`. The stdlib local
server takes `reviewer` in the body and records `local-unauthenticated`.

## Using it

Console: **Evaluate → Mapping review**. It shows per-framework progress
(org-reviewed x of mapped) and a queue filterable by framework, family, status,
and text. Select rows, write one rationale, then approve, request changes, or
reject. Each row opens a drawer with its basis, source anchor, and decision
history. Frameworks and Crosswalk link to it and show the same split.

API:

```bash
# Pending queue (proposed + needs changes), paginated
curl -s "$TRUSTOPS/api/v1/mapping-reviews/queue?framework_id=fedramp-moderate&limit=50" -H "Authorization: Bearer $KEY"
# status=all | maintainer_reviewed | org_reviewed | needs_changes | rejected ; family=<ccf family> ; safeguard_id= ; q=
curl -s "$TRUSTOPS/api/v1/mapping-reviews/decisions?safeguard_id=SG-IDENTITY-001&control_id=SOC2-CC6.1" -H "Authorization: Bearer $KEY"
curl -s "$TRUSTOPS/api/v1/mapping-reviews/summary" -H "Authorization: Bearer $KEY"
```

`POST /api/v1/mapping-reviews/decisions` takes
`{"decision", "rationale", "items": [{"safeguard_id", "framework_id", "control_id"}], "evidence_ref"}`
from a signed-in console session. A batch holds up to 500 mappings and is all or
nothing.

CLI (local lake):

```bash
grc-lake frameworks review approve --lake ./lake \
  --safeguard SG-IDENTITY-001 --framework cmmc-2-level2 --control CMMC-3.1.14 \
  --rationale "MFA evidence covers remote access routing" --reviewer grc@example.com
grc-lake frameworks review reject ...        # same flags
grc-lake frameworks review needs-changes ... # same flags
grc-lake frameworks review export --lake ./lake --format csv --out decisions.csv
grc-lake frameworks review resign --lake ./lake --previous-key-env OLD_KEY  # after a key rotation

# Coverage, queue, and OSCAL with your decisions applied
grc-lake frameworks safeguards --lake ./lake --format table
grc-lake frameworks coverage --lake ./lake
grc-lake frameworks review-queue --lake ./lake
grc-lake oscal export --component-definition --lake ./lake --out cd.json
```

## OSCAL

The component definition (see [OSCAL export](OSCAL_EXPORT.md)) emits
maintainer-reviewed mappings plus your org-reviewed ones. Each
implemented requirement carries `grc-lake-review-state`. Org-reviewed ones also
carry `grc-lake-reviewed-by`, `grc-lake-reviewed-at`, and
`grc-lake-review-decision-id`. Rejected and proposed mappings are left out.
