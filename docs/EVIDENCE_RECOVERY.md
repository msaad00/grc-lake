# Evidence recovery and checkpoints

Recovery preserves recorded history. It does not authenticate the original author
or certify control effectiveness. Keep an independently retained backup before
using these operator commands.

## Historical snapshot exports

Older versions could record an external snapshot filename without retaining a
copy in the lake. Restore missing files from a directory you select:

```sh
security-lakehouse assessment restore-snapshots --lake ./lake --source ./old-snapshot-exports
```

Every file must match its existing ledger hash, timestamp, and predecessor. The
command checks all inputs before copying, never rewrites the ledger, and refuses
symlinks, unledgered files, ambiguous names, and changed content. Repeating a
successful recovery does not duplicate history. Missing originals cannot be
reconstructed from their hashes.

## Interrupted snapshot writes

A crash after writing a snapshot but before appending its ledger entry leaves
an uncommitted file. Normal snapshot creation stays blocked; an operator can
preview the orphaned files, then explicitly quarantine them:

```sh
security-lakehouse assessment reconcile-snapshots --lake ./lake
security-lakehouse assessment reconcile-snapshots --lake ./lake --apply
security-lakehouse assessment verify-snapshots --lake ./lake
```

Preview leaves evidence unchanged. Apply validates committed history under the
snapshot writer lock, then preserves unledgered files byte-for-byte under
`gold/snapshot_recovery/<recovery-id>/files/`. Its manifest records original
names, SHA-256 hashes, and recovery timestamps. A durable pending journal allows
the same command to resume after interruption; new snapshots remain blocked
until pending recovery completes. Rerunning completed recovery is a no-op.

Quarantine never appends these files to trusted history or rewrites the ledger.
Missing or changed committed snapshots, unsafe paths, and changed pending
archive bytes stop recovery. Restore committed files from verified originals
using the command above; do not delete or reseal the ledger. Recovery hashes
files in chunks and verifies committed history before and after applying; its
I/O grows with retained history and orphaned bytes. This is local POSIX recovery,
not distributed transactions or an external integrity anchor.

## Legacy workpaper exports

```sh
security-lakehouse assessment migrate-workpaper --source ./old-export --content ./original-workpaper.json --out ./recovered-export
```

The original files must match their manifest, and the original JSON must match
its recorded content hash. Omit `--content` when the export already contains
`workpaper.json`. The destination must be new. Recovery re-renders HTML from JSON;
it never extracts assessment claims from HTML or restores server review approval.
If no original JSON survives, regenerate a new workpaper from retained evidence
and obtain a new review. Keep the old export as historical material.

## Independently retained checkpoints

```sh
security-lakehouse assessment checkpoint --lake ./lake --out ./checkpoint.json
security-lakehouse assessment verify-checkpoint --lake ./lake --checkpoint ./checkpoint.json
```

Retain the checkpoint outside the lake under separate access control, such as a
reviewer's archive or retention-locked object storage. It records the sealed
generation manifest and exact snapshot, mapping-review, and finding-tracking
ledger digests. Comparison detects replacement, truncation, or resealing relative
to that checkpoint. Normal new assessments or appended decisions also change it;
review those changes and retain a new checkpoint deliberately.

A checkpoint stored beside data an attacker can rewrite is not an external trust
anchor. These commands do not configure storage retention, provide signatures,
prove provider origin, or establish that the original data was truthful.

## Normalized evidence v4

New generations record `normalize.v4` and `control-eval.v4`. Normalized rows
include `evidence_available`, distinguishing provider evidence from the generated
bronze lineage reference. Historical v1–v3 generations remain readable without
inventing this field. Before appending v4 evidence to an existing Iceberg table,
add nullable `evidence_available` with Boolean type using your catalog's schema
migration; older rows retain null. Parquet export checks the generation's platform
tenant, while each row retains its original source account identifier.

Mapping decisions pin both the control definition and crosswalk member. Changed
definitions return affected mappings to review; an earlier approval cannot silently
approve a changed control. Explicit connector `safeguard_bindings` map event types
to compatible safeguard IDs. Framework tags alone do not establish those bindings.
