# OSCAL export

`security-lakehouse oscal export` maps TrustOps's own control model — the CCF
safeguards in `controls/safeguards.json` and the evaluated control posture in
a lake's `gold/control_posture.jsonl` — into two of NIST's
[OSCAL](https://pages.nist.gov/OSCAL/) (Open Security Controls Assessment
Language) layer models: **Component Definition** and **Assessment Results**.
OSCAL is the control/assessment interchange format auditor and GRC tooling
ecosystems consume; this export is read-only and one-way (TrustOps's model
stays the source of truth, OSCAL is never imported back in).

This is an optional export format. JSONL and the `/api/v1` contract remain the
working data formats. XML/YAML OSCAL serializations, the OSCAL Catalog,
Profile, System Security Plan, Assessment Plan, and POA&M layer models are not
implemented by this export.

## Try it locally

```bash
# Component Definition: one OSCAL component per CCF safeguard, with
# control-implementations for every reviewed framework mapping.
security-lakehouse oscal export --component-definition --out build/component-definition.json

# Assessment Results: one OSCAL finding per evaluated control in a lake.
security-lakehouse pipeline run --raw data/raw/security_events.jsonl --out build/oscal-demo-lake
security-lakehouse oscal export --assessment-results build/oscal-demo-lake \
  --out build/assessment-results.json
```

Both also stream to stdout when `--out` is omitted, and are available
read-only over the API:

```bash
curl -s http://127.0.0.1:8787/api/v1/oscal/component-definition | jq .
curl -s http://127.0.0.1:8787/api/v1/oscal/assessment-results | jq .
# Pin assessment-results to a recorded point-in-time snapshot instead of the
# current posture:
curl -s "http://127.0.0.1:8787/api/v1/oscal/assessment-results?snapshot_id=<id>" | jq .
```

## Component Definition: safeguard → implemented-requirement

Each CCF safeguard becomes one OSCAL `component` (type
`process-procedure`, since a safeguard is an operated control, not shipped
software). A safeguard's `satisfies` entries are grouped by `framework_id`
into one `control-implementation` per framework, each carrying the
`implemented-requirements` for that framework's requirements.

**Only `review_status: "reviewed"` mappings are emitted as
`implemented-requirements`.** A `proposed` (unreviewed) mapping is curation
backlog — a human has not confirmed the safeguard actually satisfies that
requirement — and OSCAL has no field to mark an implemented requirement as
unconfirmed. Emitting a proposed mapping would read to auditor tooling as an
asserted claim TrustOps has not verified. This mirrors the same
`reviewed_only` distinction `safeguards_by_requirement()` already enforces for
attestable framework coverage (`src/security_lakehouse/safeguards.py`). A
safeguard whose only mappings are proposed still becomes a component (nothing
is silently dropped); it simply carries no `control-implementations`.

With `--lake` (CLI) or through the API, the export also includes mappings your
organization approved and leaves out any it rejected. Every implemented
requirement carries a `trustops-review-state` prop (`maintainer-reviewed` or
`org-reviewed`), and org-reviewed ones name the reviewer, decision time, and
decision id. See [Mapping review](MAPPING_REVIEW.md).

TrustOps control ids are not always valid OSCAL tokens — HIPAA ids carry
parentheses (`HIPAA-164.308(a)(1)(ii)(A)`), which the OSCAL token grammar
forbids. The export sanitizes these into a valid token
(`HIPAA-164.308-a-1-ii-A`) and always records the original id verbatim in a
`trustops-control-id` prop, so nothing is lost to the sanitization.

## Assessment Results: control posture → finding

`--assessment-results <lake>` reads `gold/control_posture.jsonl` — the
per-control `pass`/`fail`/`stale`/`not_evaluated` rows the pipeline writes for
every generation — and emits one OSCAL `finding`, backed by one
`observation`, per control:

| TrustOps `status` | OSCAL `target.status.state` | `reason` |
| ----------------- | --------------------------- | -------- |
| `pass`            | `satisfied`                 | `pass`   |
| `fail`            | `not-satisfied`             | `fail`   |
| `stale`           | `not-satisfied`             | `other`  |
| `not_evaluated`   | `not-satisfied`             | `other`  |

OSCAL only has two objective states. A control with stale evidence or no
active control definition is reported `not-satisfied`, never `satisfied` — an
auditor reading the export must never see an unconfirmed or unevaluated
control reported as passing. The original TrustOps status is preserved
verbatim in a `trustops-status` prop on the finding.

`--snapshot <id>` pins the result's `evaluated_at` and content version to a
point-in-time snapshot written by `security-lakehouse assessment snapshot`.
The findings themselves always come from the lake's _current_
`gold/control_posture.jsonl`: snapshots persist aggregate framework scores and
open violations, not a full per-control row set, so there is no frozen
per-control detail to reconstruct for an older snapshot. Without `--snapshot`,
this distinction does not apply — the export reflects the current posture
throughout.

`import-ap.href` references the content-addressed catalog bundle
(`urn:trustops:catalog-bundle:<sha256>`) that was in force for the
assessment — TrustOps has no separate OSCAL Assessment Plan document, so this
is the closest equivalent of "what was assessed against".

## Validation

`tests/test_oscal.py` validates both models structurally against the vendored
OSCAL v1.2.3 JSON Schema in `controls/oscal/` (see
`controls/oscal/README.md` for provenance), and explicitly asserts that a
`proposed` safeguard mapping is never emitted as an
`implemented-requirement`.

Format reference: [OSCAL documentation](https://pages.nist.gov/OSCAL/) ·
[usnistgov/OSCAL](https://github.com/usnistgov/OSCAL) ·
[usnistgov/oscal-content](https://github.com/usnistgov/oscal-content) (example
documents this export's shape was checked against).
