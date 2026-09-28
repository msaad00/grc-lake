# Framework expansion plan

TrustOps ships **source-linked** framework packs: local control IDs, short internal titles, evidence requirements, and official citations — never paywalled standard text.

## Implementation status model

| Status                        | Meaning                                              | Controls in catalog | Console posture       |
| ----------------------------- | ---------------------------------------------------- | ------------------- | --------------------- |
| `implemented_full_pack`       | Seeded controls + reviewed mappings + evidence hints | Yes                 | Included in readiness |
| `implemented_limited_mapping` | Honest seed subset with public-source citations      | Yes (subset)        | Included              |
| `referenced_only`             | Official source linked; analyst/MCP skill only       | No                  | Listed, not scored    |
| `planned`                     | Roadmap entry with zero seeded controls              | No                  | Listed as planned     |

Validation lives in `validate_catalog()` (`src/security_lakehouse/catalog.py`) and `tests/test_framework_implementation_status.py`.

## Shipped today (20 implemented)

See [FRAMEWORK_COVERAGE.md](./FRAMEWORK_COVERAGE.md) for the live matrix. Current implemented frameworks:

- SOC 2, NIST AI RMF, ISO 27001, ISO 27017, ISO 42001, NIST CSF 2.0
- NIST SP 800-53 Rev 5 (full catalog, baseline-tagged), NIST RMF (SP 800-37 Rev 2)
- FedRAMP Moderate, CMMC 2 Level 2, CIS AWS Foundations, CIS Controls v8.1 (all 18 controls)
- NIST SP 800-171 Rev 3 (all 97 requirements, with NIST's Rev 2 to Rev 3 relationships)
- GDPR, HIPAA Security Rule, EU AI Act, PCI DSS v4.0.1 (limited mapping: all 12 principal requirements)
- NIS2 (limited mapping: Article 21(2)(a)–(j) and Article 23 reporting) and DORA (limited mapping: 99 entity obligations across Articles 5–30 and 45)
- ISO/IEC 27701:2025 (limited mapping: 10 of 78 Annex A controls verified by two independent non-vendor sources)

## Planned next (registry only)

| Framework ID     | Official source                                                                                        | Target stream       | Notes                                                                                                           |
| ---------------- | ------------------------------------------------------------------------------------------------------ | ------------------- | --------------------------------------------------------------------------------------------------------------- |
| `iso-27701-2019` | [ISO/IEC 27701:2019](https://www.iso.org/standard/71670.html)                                          | Privacy (withdrawn) | Withdrawn on publication of the 2025 edition (2025-10-14); `superseded_by: iso-27701-2025`, no controls seeded  |
| `soc1`           | [AICPA SOC 1](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2) | Financial reporting | Planned boundary is explicit in the registry; requires service-specific ICFR objectives before seeding controls |

### ISO/IEC 27001 clauses 4–10

The pack seeds the 93 Annex A controls. The ISMS requirements in clauses 4–10
(context, leadership, planning, support, operation, performance evaluation,
improvement) are not seeded yet: the official clause list is only in the
licensed standard, and ISO's online browsing platform is not an open source
this repository can pin. Seed them once a licensed copy is available to verify
identifiers against.

### CIS benchmarks beyond AWS

CIS Microsoft Azure and Google Cloud Platform Foundations Benchmarks are not
catalogued. Like CIS AWS, their recommendation IDs come from registration-gated
PDFs; add them when those are available to verify against.

### ISO/IEC 27701:2025: why only 10 of 78 controls

ISO publishes no open list of the 2025 Annex A identifiers. The pack seeds a
control only when two independent non-vendor sources (standards bodies or
accredited certification bodies) agree on its identifier and short title; vendor
pages count only as extra corroboration. BSI's Annex A tables and Schellman's
certification guidance agree on 10 controls. The other 68 are listed as gaps
in `frameworks/packs/data/iso_27701_2025.json` and get seeded once a second
source, or a licensed copy, verifies them. See
[FRAMEWORK_PACKS.md](./FRAMEWORK_PACKS.md#isoiec-277012025-iso-27701-2025---pack-iso-27701).

### SOC 1: why it stays planned

SOC 1 (SSAE 18 / AT-C 320) reports test **control objectives the service
organization writes for its own services**; AICPA publishes no numbered SOC 1
control catalog. Seeding one would break rule 1 below, so `soc1` stays
`planned` with zero controls. The ICFR-relevant general controls it would test
(control environment, logical access, change management) are already covered
through SOC 2 common criteria CC1–CC8, which map to the COSO 2013 principles.
A future SOC 1 surface would let a tenant author its own objectives rather
than ship a seeded pack.

## Expansion rules (do not skip)

1. **No invented controls** — every seeded control must map to an official article/requirement ID.
2. **Evidence requirements** — each new control ships `required_evidence_types` and connector hints.
3. **Tests** — add catalog integrity, mapping coverage, and at least one pipeline fixture event per new evidence type.
4. **Copyright guardrails** — reproduce identifiers and short titles only; link official sources.
5. **Planned stays honest** — `planned` frameworks must have `seeded_control_count = 0` until a pack PR lands. A planned framework may expose an evidence focus and next step, but those are guidance—not controls or evaluated coverage.

## Adding a new pack (contributor checklist)

1. Add registry row with `implementation_status` and `official_source_url`.
2. Add pack JSON under `frameworks/packs/data/` (or extend existing pack).
3. Run `make coverage-doc`, `uv run security-lakehouse catalog lock`, then `make validate` (catalog validation + bundle-lock verify).
4. Add `tests/test_framework_packs.py` coverage for the new pack slug.
5. Update `docs/FRAMEWORK_PACKS.md` with evidence connector hints.

## Analyst-only / MCP skills

Frameworks marked `referenced_only` or `planned` remain visible in `/console/frameworks/` but do not affect posture until a pack ships. Agents should use `get_framework_coverage` and cite official URLs rather than inventing control text.
