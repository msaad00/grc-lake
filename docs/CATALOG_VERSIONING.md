# Catalog versioning & audit pinning

Frameworks and controls are living artifacts. Regulations get revised, mappings
get re-reviewed, controls are retired and superseded. An audit must be able to
state **exactly** which control text and which framework version were in force
during its window — and reproduce that view later. This is how compliance platforms pin
an audit to a control library version and how CSPM rule packs ship versioned,
checksummed content.

GRC Lake makes the control catalog **bivalent-temporal** without changing the
shape of the active set.

## The model

### Frameworks (`frameworks/registry.json`)

Each framework already declares `version`, `effective_date`, `superseded_by`,
plus provenance (`official_source_url`, `source_sha256`, `pulled_at`,
`sync_cadence_days`). The sync job re-fetches the official source, recomputes
the sha256, and — only when the body changes — updates `source_sha256` and
`pulled_at` (so `pulled_at` is when the current content was first seen, and an
unchanged source leaves the registry untouched) and appends a row to
`frameworks/history.jsonl` so the history of _what the upstream said when_
survives even before a human assigns a new version label. The file does not
exist until the first upstream change is detected; the sync job creates it on
that first append.

### Controls (`controls/catalog.json` + `controls/history.jsonl`)

`controls/catalog.json` stays the **current** set — one row per `control_id`.
Every control now carries version fields (schema `trustops.control.v2`):

| field              | meaning                                     |
| ------------------ | ------------------------------------------- |
| `version`          | semver of this control version (`1.0.0`)    |
| `valid_from`       | ISO date the version took force             |
| `valid_to`         | ISO date it was retired (`null` = in force) |
| `supersedes`       | `control_id@version` this version replaced  |
| `superseded_by`    | successor reference, set on retirement      |
| `change_reason`    | why this version exists                     |
| `lifecycle_status` | `active` \| `draft` \| `retired`            |

`controls/history.jsonl` is an **append-only** ledger of retired versions.
Retiring never deletes — it closes `valid_to`, stamps `lifecycle_status=retired`,
and appends the row to history. Past findings and snapshots keep referencing the
old version id, so historical audits stay reproducible while new evaluations use
the latest version.

```python
from security_lakehouse.catalog_versions import retire_control

# Retire SOC2-CC6.1 v1.0.0 and replace it with a revised body (auto v1.1.0).
retire_control(
    "SOC2-CC6.1",
    change_reason="AICPA 2025 points-of-focus revision",
    successor={**revised_control_body},
)
```

## Querying history & point-in-time

```bash
# Every version of a control (retired + active), oldest-first
grc-lake controls history --control-id SOC2-CC6.1

# The exact control versions in force on an audit date
grc-lake controls as-of --date 2026-03-15
```

`controls_as_of(date)` reconstructs the set of control versions where
`valid_from <= date` and (`valid_to` is null or `date < valid_to`). This is the
query an audit pins to.

## The catalog bundle (content-addressed lock)

A **catalog bundle** is the lockfile that ties an audit to a point in catalog
evolution: a deterministic sha256 over the framework registry + active controls

- reviewed crosswalk, with per-component digests.

```bash
grc-lake catalog bundle            # print the active bundle header
grc-lake catalog bundle --as-of 2026-03-15   # historical reconstruction
grc-lake catalog lock              # (re)write controls/bundle.lock.json
grc-lake catalog verify            # CI guard: catalog vs committed lock
```

`controls/bundle.lock.json` is committed. `make validate` runs `catalog verify`,
so any edit to a framework, control, or crosswalk entry that isn't reflected in
the lockfile fails CI and forces human ratification — the same drift-ratification
pattern the framework sync job uses.

Component digests cover **full bodies**, so even a title fix that skipped a
version bump drifts the lock.

## Audit pinning

`write_assessment_snapshot()` embeds the active catalog bundle under
`catalog_bundle`. Because the snapshot's `assessment_hash` covers every field,
the pin is tamper-evident along with the rest of the hash-chained snapshot
ledger. Re-running an assessment against a snapshot reproduces the exact controls
and framework versions it was evaluated with.

## API (headless / agent)

| route                                       | returns                             |
| ------------------------------------------- | ----------------------------------- |
| `GET /api/v1/catalog/bundle?as_of=&full=`   | bundle header (or full manifest)    |
| `GET /api/v1/controls/as-of?as_of=`         | control versions in force on a date |
| `GET /api/v1/controls/{control_id}/history` | every version of a control          |
