# Framework Packs

TrustOps ships **framework packs** — complete criterion/subcategory catalogs with
reviewed mappings, evidence requirements, and evaluation rules. Packs are the
fastest path to managed GRC-style **100% framework ID coverage** while other
frameworks stay seed-and-expand.

## Full packs (100% ID coverage)

| Pack                         | Framework ID          | Controls                                                                              | Official source                                                                                                                                    |
| ---------------------------- | --------------------- | ------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| SOC 2 Common Criteria        | `soc2`                | **33** (CC1.1–CC9.2)                                                                  | [AICPA TSC 2017/2022](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022)                |
| SOC 2 TSC extensions         | `soc2`                | **28** supplemental (A1, C1, PI1, P1–P8) — **61 total**                               | same                                                                                                                                               |
| NIST AI RMF 1.0              | `nist-ai-rmf`         | **72** (all GOVERN/MAP/MEASURE/MANAGE subcategories)                                  | [NIST AI RMF 1.0](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10)                                   |
| NIST CSF 2.0 Core            | `nist-csf-2.0`        | **106** subcategories (GOVERN through RECOVER)                                        | [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)                                                                            |
| FedRAMP Moderate foundation  | `fedramp-moderate`    | **287** (NIST SP 800-53 Rev 5 Moderate baseline)                                      | [NIST SP 800-53B](https://csrc.nist.gov/publications/detail/sp/800-53b/final)                                                                      |
| NIST SP 800-53 Rev 5 (5.2.0) | `nist-800-53-rev5`    | **1,014** active controls + enhancements, 20 families, LOW/MODERATE/HIGH/PRIVACY tags | [NIST SP 800-53 Rev 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) (pinned OSCAL catalog)                                                  |
| NIST RMF (SP 800-37 Rev 2)   | `nist-rmf-800-37r2`   | **47** tasks (Prepare → Monitor)                                                      | [NIST SP 800-37 Rev 2](https://csrc.nist.gov/pubs/sp/800/37/r2/final)                                                                              |
| CIS AWS Foundations v3.0     | `cis-aws` / `cis_aws` | **62** recommendations                                                                | [CIS AWS Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)                                                                      |
| CMMC 2.0 Level 2             | `cmmc-2-level2`       | **110** practices (NIST SP 800-171 Rev 2)                                             | [NIST SP 800-171 Rev 2](https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final) / [CMMC](https://dodcio.defense.gov/CMMC/Documentation/) |
| NIST SP 800-171 Rev 3        | `nist-800-171-rev3`   | **97** requirements, 17 families                                                      | [NIST SP 800-171 Rev 3](https://csrc.nist.gov/pubs/sp/800/171/r3/final) (pinned OSCAL catalog)                                                     |
| ISO/IEC 27001:2022 Annex A   | `iso-27001-2022`      | **93** controls                                                                       | [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)                                                                                           |
| ISO/IEC 27017:2015 Cloud     | `iso-27017-2015`      | **47** clauses (40 ISO 27002 + 7 CLD)                                                 | [ISO/IEC 27017:2015](https://www.iso.org/standard/43757.html)                                                                                      |
| ISO/IEC 42001:2023 Annex A   | `iso-42001-2023`      | **38** AI controls                                                                    | [ISO/IEC 42001:2023](https://www.iso.org/standard/42001)                                                                                           |

**Important:** 100% here means **every official criterion ID is seeded, mapped,
and evaluable in TrustOps**. It does not mean certification, audit opinion, or
that every point-of-focus has bespoke automated evidence yet.

**FedRAMP note:** FedRAMP Rev 5 Moderate authorization selects **323** controls
from NIST SP 800-53 Rev 5 with FedRAMP overlays. This pack seeds the **NIST
Moderate baseline (287 controls)** — the authoritative OSCAL control set that
forms the FedRAMP Moderate foundation. FedRAMP-specific parameter overlays ship
in a follow-up.

**NIST SP 800-53 note:** `nist-800-53-rev5` is the full Rev 5.2.0 catalog (every
active control and enhancement; 182 withdrawn are excluded), generated from a
pinned commit of `usnistgov/oscal-content` by `tools/sync_nist_800_53.py`. Each row
carries `nist_baselines` (LOW 149, MODERATE 287, HIGH 370, PRIVACY 96), and the
MODERATE set is test-pinned to equal the `fedramp-moderate` pack. Every CCF
safeguard mapped to a FedRAMP control is also mapped to the identical 800-53
control, as **proposed**. Identifier mappings are source-reconciled, not
human-reviewed, so the framework stays `implemented_limited_mapping` and the
readiness view stops it at the `mapped` gate until review.

**NIST SP 800-171 Rev 3 note:** `nist-800-171-rev3` holds all 97 active Rev 3
requirements (03.01.01 to 03.17.03; withdrawn identifiers excluded), generated by
`tools/sync_nist_800_171r3.py` from the OSCAL catalog at `usnistgov/oscal-content`
commit `78650f0`. The same tool reads NIST's published
[Rev 2 to Rev 3 change analysis](https://csrc.nist.gov/files/pubs/sp/800/171/r3/final/docs/sp800-171r2-to-r3-analysis.xlsx)
and records, on each row, its Rev 2 predecessors (`carried_forward` or
`incorporated_into`, with NIST's change rating). The 11 Rev 2 requirements NIST
did not carry forward are listed under `r2_not_carried` with NIST's reason, so all
110 are accounted for. One analysis row labels the Rev 2 system security plan
requirement `3.11.4` instead of `3.12.4`; it is recorded under
`source_anomalies` and not used. The catalog, the PDF and the workbook are pinned
by sha256.

`cmmc-2-level2` stays on Rev 2. A CCF safeguard that carries a Rev 2 practice
now also carries its Rev 3 successor as **proposed**, citing the analysis row,
when the requirement text still supports it; other Rev 3 mappings are judgment
calls citing the Rev 3 PDF. The 14 requirements with no honest safeguard home are
listed under `unmapped`: eight sit on narrow Rev 2 crosswalk lanes that tests pin
to their current members. Evidence types and connector hints are set per family
(`framework_family_connectors["nist-800-171-rev3"]`, keyed `03.01` … `03.17`).

## Sync packs into the catalog

```bash
security-lakehouse frameworks sync-packs
# or one pack:
security-lakehouse frameworks sync-packs --pack nist-csf-2.0
security-lakehouse frameworks sync-packs --pack fedramp-moderate
security-lakehouse frameworks sync-packs --pack cis-aws
security-lakehouse frameworks sync-packs --pack cmmc-2-level2
security-lakehouse frameworks sync-packs --pack iso-27001-2022
security-lakehouse frameworks sync-packs --pack iso-27017-2015
security-lakehouse frameworks sync-packs --pack iso-42001-2023
make framework-packs
```

This merges pack rows into:

- `controls/catalog.json`
- `mappings/control_articles.json`
- `mappings/control_map.json`
- `controls/bundle.lock.json` (via bundle recompute)
- `frameworks/verified_article_ids.json` (regenerate from mappings after sync)

Hand-authored controls (e.g. richer `SOC2-CC6.1` evidence text) are **preserved**
when the `control_id` already exists.

Pack source data for every full and limited pack, plus connector hints, lives
under `frameworks/packs/data/` (see that directory's `README.md` for the file
list). Connector hints power framework drill-down recommendations
(`evidence_hints.py`).

## Manifest schema

Every framework pack is **manifest-driven**: a framework's control
identifiers, titles, and source citation are data in a JSON file under
`frameworks/packs/data/`, not a bespoke Python function. Each pack's
`*_specs()` function (in `framework_packs.py` or `limited_packs.py`) is a
thin wrapper: it calls
`pack_from_manifest(manifest_path, transform=...)` — see
`src/security_lakehouse/pack_manifest.py` — passing a small, named,
per-framework **transform** function that handles whatever logic doesn't
belong in data (ID normalization, risk-domain/owner lookups, evidence
wording).

A manifest is a JSON object with:

- `schema` (optional) — `"trustops.framework_pack_manifest.v1"`.
- `source` — the pinned citation: at minimum a `url`; the `nist_csf_2_core.json`
  precedent also pins a `sha256` digest and a `locator` for source-integrity
  testing (see `tests/test_csf_source_integrity.py`).
- a rows key (`"rows"` by default; `pack_from_manifest(..., rows_key=...)`
  can point at another key, e.g. pre-existing files' `"requirements"` or
  `"controls"`) holding either:
  - an array of objects, `[{"id": "1.1", "title": "..."}, ...]` — the
    default new-manifest shape, and the shape already used by
    `cis_aws_v3.json`, `cmmc_2_level2.json`, and `iso_27017_2015.json`.
    Extra per-row fields (e.g. a limited pack's `risk_domain`/`owner`/
    `asset_types`) pass through to the transform via `row.extra`.
  - an object mapping identifier -> title, `{"GV.OC-01": "...", ...}` — the
    `nist_csf_2_core.json` precedent's `"outcomes"` shape.
  - an array of plain identifier strings, `["AC-1", "AC-2", ...]` — for
    frameworks with no distinct per-ID title text (e.g.
    `nist_800_53_rev5_moderate.json`'s `"control_ids"`).

### Add a new framework

1. Add `frameworks/packs/data/<framework>.json` with the framework's official
   identifiers (and titles, where distinct per-ID text exists — never
   transcribe licensed normative text, short internal titles only).
2. Write a small transform function, e.g. `_<framework>_row_transform(row:
PackManifestRow) -> PackControlSpec`, covering whatever isn't flat data:
   ID normalization, a risk-domain/owner lookup, `evidence_requirement`
   wording. Reuse `_soc2_owner`/`_soc2_assets`/`_soc2_evaluation_rule` where
   the framework's evaluation shape matches the existing ones.
3. Add `<framework>_specs() -> list[PackControlSpec]` that calls
   `pack_from_manifest(PACK_DATA_DIR / "<framework>.json", transform=...)`,
   and register it in `PACK_BUILDERS` (or `LIMITED_PACK_BUILDERS` for a
   partial-coverage pack).
4. Write a row-level identity test if converting an existing framework, or a
   coverage test (count + identifier set) for a new one — see
   `tests/test_framework_packs.py` and `tests/test_pack_manifest.py`.
5. Run `security-lakehouse frameworks sync-packs --pack <framework>` then
   `security-lakehouse catalog verify` (regenerate the lockfile per the
   command above if it reports stale).

## Verify coverage

```bash
security-lakehouse frameworks coverage --format markdown > docs/FRAMEWORK_COVERAGE.md
security-lakehouse catalog verify
```

Full packs should show **100% seeded mapping coverage** with `seeded_control_count`
equal to the pack sizes above.

## Limited-mapping packs (GDPR, HIPAA, PCI, EU AI Act, CIS Controls, ISO 27701, NIS2, DORA)

Run `frameworks sync-packs --pack gdpr --pack hipaa --pack pci-dss --pack eu-ai-act`
to merge expanded honest subsets (20 GDPR articles, 18 HIPAA sections, 12 PCI
requirements, 16 EU AI Act articles as of v0.2.x). These are **not** full
official catalogs — see [Framework Coverage](FRAMEWORK_COVERAGE.md) for counts.

PCI DSS cites **v4.0.1** and seeds all 12 principal requirements at the
requirement level (`Req-1` … `Req-12`). It stays `implemented_limited_mapping`:
the x.y / x.y.z sub-requirements are not seeded, because the PCI SSC standard
is distributed under a license click-through and there is no official
machine-readable identifier source to pin them to. The v4.0-citing control
versions (1.0.0) remain in `controls/history.jsonl`, so as-of views of audits
before 2026-09-23 still show the v4.0 citation.

CIS Controls v8.1 (`cis-controls-v8.1`, `--pack cis-controls`) seeds all 18
controls from the public [CIS Controls list](https://www.cisecurity.org/controls/cis-controls-list).
The 153 safeguards are not seeded: CIS distributes them only in a
registration-gated download, so there is no open source to verify identifiers
against. Rows are source-reconciled and `proposed`.

### ISO/IEC 27701:2025 (`iso-27701-2025`, `--pack iso-27701`)

The 2025 edition (published 2025-10-14) is a standalone privacy management
system standard and replaced ISO/IEC 27701:2019, which is withdrawn (2019
certificates stay valid until October 2028). `iso-27701-2019` stays `planned`
with zero controls and `superseded_by: iso-27701-2025`.

ISO publishes no open list of the Annex A identifiers, so each seeded control
must have its identifier and short title agree across **two independent
non-vendor sources** (a standards body or an accredited certification body).
Vendor pages corroborate but never count toward the two. Every source is pinned
in `frameworks/packs/data/iso_27701_2025.json` under `verification_sources`
(URL, publisher, kind, sha256, pulled_at, locator), and every row lists the
sources that verify it in `verified_by`.

Today 10 of the 78 Annex A controls meet that rule: BSI's Annex A tables and
Schellman's certification guidance both name them. The other 68 are listed
under `gaps` by identifier only, with no title, and stay unseeded until a
second source verifies them. Clauses 4–10 are not seeded. Titles follow the
same copyright approach as the ISO 27001, 27017 and 42001 packs: identifiers
and short titles only, never control text or guidance.

Each control carries `required_evidence_types`, which control tests use when
no program configures that control. Connector hints come from
`evidence_connector_hints.json` (`framework_family_connectors["iso-27701-2025"]`,
keyed by Annex A subsection):

| Controls                                              | Evidence types                               | Connector hints                                            |
| ----------------------------------------------------- | -------------------------------------------- | ---------------------------------------------------------- |
| A.1.2.8 Joint PII controller                          | `privacy.agreement`                          | managed-local-evidence, object-storage-evidence            |
| A.1.4.7, A.2.4.2 Temporary files                      | `cloud.config`, `compliance.evidence_bundle` | aws/gcp/azure-posture, object-storage-evidence             |
| A.1.5.2, A.2.5.2 Basis for PII transfer               | `privacy.transfer_record`                    | managed-local-evidence, object-storage-evidence, ticketing |
| A.1.5.5, A.2.5.4 Records of PII disclosure            | `privacy.disclosure_record`                  | managed-local-evidence, object-storage-evidence, ticketing |
| A.2.2.5 Infringing instruction                        | `remediation.ticket`                         | ticketing, jira-ticketing, managed-local-evidence          |
| A.2.5.7, A.2.5.9 Subcontractor disclosure and changes | `privacy.subprocessor_register`              | managed-local-evidence, object-storage-evidence, ticketing |

Eight controls map to existing CCF safeguards as `proposed` (data retention,
data inventory, third-party risk, cross-border transfer). The joint-controller
and infringing-instruction controls have no matching safeguard yet.

### NIS2 (`nis2-2022-2555`, `--pack nis2`) and DORA (`dora-2022-2554`, `--pack dora`)

Both packs cite the English Official Journal text, pinned by sha256 to the PDF
the EU Publications Office serves for the CELEX number
(`frameworks/packs/data/nis2_2022_2555.json`, `dora_2022_2554.json`, with the
ELI, CELEX and OJ reference). Identifiers are article, paragraph and point
(`NIS2-Art21.2(a)`, `DORA-Art9.4(c)`, `DORA-Art7`); titles are short
paraphrases, and the legal text is not reproduced.

- **NIS2** seeds 17 entity obligations: the ten Article 21(2) risk-management
  measures (a)–(j) and the Article 23(1), (2) and (4)(a)–(e) reporting duties.
  All 17 map to existing safeguards as proposed.
- **DORA** seeds 99 financial-entity obligations at paragraph level: ICT risk
  management (Articles 5–14 and 16), incident management and reporting
  (17–19), resilience testing (24–27), ICT third-party risk (28–30) and
  information sharing (45). Rows with a narrower scope carry `applies_to`
  (non-microenterprises, TLPT-designated entities, Article 16(1) entities).
  79 map to existing safeguards as proposed; the 20 without an honest home,
  including every threat-led penetration testing row, are listed under
  `unmapped`. Authority and ESA provisions (Articles 15, 20–23 and the
  mandate paragraphs) are listed under `not_seeded`.

Commission Delegated Regulation (EU) 2024/1774, the RTS on the ICT risk
management framework, is pinned under DORA `related_acts` for a follow-up pack
and not seeded. NIS2 Implementing Regulation (EU) 2024/2690 is recorded the
same way.

| Evidence type                | Used by                                       | Connector hints                                   |
| ---------------------------- | --------------------------------------------- | ------------------------------------------------- |
| `incident.regulatory_report` | NIS2 Art 23, DORA Art 19                      | ticketing, jira-ticketing, managed-local-evidence |
| `resilience.test_report`     | NIS2 Art 21(2)(c), DORA Art 11–12, 24–27      | aws-posture, managed-local-evidence               |
| `third_party.register`       | NIS2 Art 21(2)(d), DORA Art 8(5), 8(6), 28–30 | managed-local-evidence, ticketing                 |

Other rows reuse `cloud.config`, `identity.access_review`, `detection.alert`,
`vulnerability.finding`, `remediation.ticket`, `audit.chain` and
`compliance.evidence_bundle`. Hints are keyed per NIS2 row and per DORA article.

## Other frameworks (add as you go)

SOC 1 remains **planned** in the registry. Expand additional
frameworks incrementally using the same control schema. SOC 1 has no official
control catalog to seed from (see
[Framework expansion plan](FRAMEWORK_EXPANSION_PLAN.md#soc-1-why-it-stays-planned)).

## Custom frameworks

Add customer-specific or internal frameworks under `frameworks/custom/`:

1. Copy `frameworks/custom/example.registry.json` and `example.controls.json`.
2. Register the framework in your deployment's data directory or merge into
   `frameworks/registry.json`.
3. Add controls with full provenance fields (see `controls/catalog.json`).
4. Run `security-lakehouse controls provenance` and `security-lakehouse catalog verify`.

Custom packs can reuse evaluation rule aliases from `policy.py` and map to
your connectors' evidence types.

## Evaluation rules by domain

Pack-generated controls use deterministic rule aliases:

| Risk domain                                        | Default rule                                 |
| -------------------------------------------------- | -------------------------------------------- |
| identity, monitoring, controls-operations, ai-risk | `fail_when_open_violation_or_stale_evidence` |
| vendor-risk                                        | `fail_when_high_severity_open`               |
| governance, risk-management, ai-governance         | `fail_when_missing_evidence`                 |

Tune per control after sync by editing `evaluation_rule` in the catalog.

## Roadmap

- FedRAMP **Rev 5 overlay** controls beyond NIST Moderate (323-selected set)
- SOC 2 **Availability / Confidentiality / Processing Integrity / Privacy** TSC
- Pack-specific evidence requirement templates linked to connector catalogs

See [ROADMAP.md](../ROADMAP.md).
