# Common Control Framework

A Common Control Framework consolidates many regulatory requirements into one set
of operational safeguards. You operate the safeguard; framework coverage is
derived from it.

TrustOps is adopting this model. This document describes the target, what exists
today, and how the rest gets there.

The live, generated **[Framework Coverage Matrix](FRAMEWORK_COVERAGE.md)** shows
per-framework coverage split into _evaluatable_ (any safeguard mapping) vs
_attestable_ (human-reviewed — the only coverage an auditor accepts); the gap
between them is the mapping-review backlog.

## Why the catalog alone is not a CCF

`controls/catalog.json` is framework-first: 2031 requirements, each carrying its
own `framework_id` **and its own `evidence_requirement`** — 2031 distinct evidence
statements for 2031 controls, none shared.

That last number is the whole problem. Because no two requirements share an
evidence statement, answering SOC 2, ISO 27001, and FedRAMP means answering the
same operational question three times, in three places, with three review trails.

`mappings/framework_equivalence.json` was a first attempt at relief, linking
requirements that address the same theme. But it is a crosswalk _laid over_ a
framework-first catalog. It annotates the duplication instead of removing it.

## The model

A **safeguard** is the operated object. It carries one evidence requirement, one
evaluation rule, one owner — and it satisfies many framework requirements.

```
safeguard  SG-IDENTITY-001  "Logical access and MFA"
  evidence_requirement   (one statement, operated once)
  evaluation_rule        (one test)
  satisfies
    SOC2-CC6.1            soc2              primary
    ISO27001-A.5.15       iso-27001-2022    equivalent
    NIST-CSF-PR.AA-01     nist-csf-2.0      equivalent
    FEDRAMP-AC-2          fedramp-moderate  equivalent
    CIS-AWS-1.10          cis_aws           equivalent
    HIPAA-164.308(a)(4)   hipaa-security-rule equivalent
```

Six requirements, one thing to operate.

### The relationship is many-to-many, in both directions

One safeguard satisfying many requirements is the point. The reverse also
happens: **SOC2 CC7.2 and PCI-DSS-10 each need two safeguards** — detection _and_
audit logging.

That forces a semantic decision, and it is the one worth arguing about:

> A framework requirement is met only when **every** safeguard mapped to it passes.

The alternative — any one passing is enough — would let a green logging safeguard
report a monitoring requirement as satisfied. That is a false attestation reaching
an auditor, which is the failure this system exists to prevent.

`requirement_status()` also distinguishes **`unmapped`** from `fail`. "We have not
modelled this yet" and "we tested it and it failed" are different answers, and
collapsing them would overstate both coverage and failure.

## Control families

Every safeguard belongs to exactly one family defined in
[`controls/families.json`](../controls/families.json); the validator rejects any
other value. Each family records the NIST SP 800-53 families and CIS Controls it
corresponds to, and `GET /api/v1/ccf/coverage` returns those definitions with the
family ledger.

| Family                    | ID                         | Safeguards | NIST SP 800-53 families | CIS Controls |
| ------------------------- | -------------------------- | ---------: | ----------------------- | ------------ |
| AI governance             | `ai-governance`            |          6 | —                       | —            |
| Availability and recovery | `availability`             |          1 | CP                      | 11           |
| Change management         | `change-management`        |          3 | CM                      | —            |
| Configuration management  | `configuration-management` |          4 | CM                      | 2, 4         |
| Data protection           | `data-protection`          |          3 | SC, MP                  | 1, 3         |
| Detection                 | `detection`                |          2 | SI                      | 10, 13       |
| Governance                | `governance`               |          8 | PL, PM                  | —            |
| Identity and access       | `identity`                 |          5 | AC, IA                  | 5, 6         |
| Incident response         | `incident-response`        |          4 | IR                      | 17           |
| Audit logging             | `logging`                  |          2 | AU                      | 8            |
| Network security          | `network-security`         |          1 | SC                      | 12           |
| People security           | `people-security`          |          2 | AT, PS                  | 14           |
| Physical security         | `physical-security`        |          2 | PE                      | —            |
| Privacy                   | `privacy`                  |          5 | PT                      | —            |
| Processing integrity      | `processing-integrity`     |          3 | SI                      | —            |
| Risk management           | `risk-management`          |         10 | RA, CA, PM              | 18           |
| Secure architecture       | `secure-architecture`      |          4 | SA, SC                  | —            |
| Secure development        | `secure-development`       |          3 | SA                      | 16           |
| System maintenance        | `system-maintenance`       |          4 | MA                      | —            |
| Third-party risk          | `third-party-risk`         |          3 | SR, SA                  | 15           |
| Vulnerability management  | `vulnerability-management` |          3 | RA, SI                  | 7            |

## Where it stands

```
$ security-lakehouse frameworks safeguards --format table
78 safeguards map 1182 of 2031 requirements (58.2%) — 350 reviewed (17.2%), 832 proposed
```

A mapping is **reviewed** once a human has confirmed the requirements are the
same obligation. **Proposed** mappings were matched by title theme and are
reported separately, because a compliance product must never count unconfirmed
work as attested coverage. `safeguards_by_requirement(reviewed_only=True)` is
what attestation should read — so "SOC 2 is fully mapped" and "SOC 2 is fully
reviewed" are different claims, and only the second is one to make to an
auditor.

Curation is ordered by what teams are actually audited and certified against.

The family ledger is available through `security-lakehouse frameworks safeguards`
and `GET /api/v1/ccf/coverage`. It groups the operated safeguards by their
`risk_domain`, then reports the frameworks touched plus reviewed and proposed
mapping counts. A family with proposed mappings is **evaluatable**, not
attestable; the endpoint keeps those states separate so a broad family view
cannot become a false certification claim.

| Framework           | Requirements | Mapped |    Pct |
| ------------------- | -----------: | -----: | -----: |
| cmmc-2-level2       |          110 |    110 | 100.0% |
| eu-ai-act-2024-1689 |           15 |     15 | 100.0% |
| hipaa-security-rule |           18 |     18 | 100.0% |
| pci-dss-v4          |           12 |     12 | 100.0% |
| soc2                |           61 |     61 | 100.0% |
| nist-rmf-800-37r2   |           47 |     46 |  97.9% |
| nist-csf-2.0        |          106 |    101 |  95.3% |
| gdpr-2016-679       |           20 |     19 |  95.0% |
| iso-27017-2015      |           47 |     44 |  93.6% |
| fedramp-moderate    |          287 |    262 |  91.3% |
| iso-27001-2022      |           93 |     81 |  87.1% |
| cis-controls-v8.1   |           18 |     15 |  83.3% |
| cis_aws             |           62 |     51 |  82.3% |
| iso-27701-2025      |           10 |      8 |  80.0% |
| iso-42001-2023      |           39 |     26 |  66.7% |
| nist-ai-rmf         |           72 |     28 |  38.9% |
| nist-800-53-rev5    |         1014 |    285 |  28.1% |

### What a safeguard applies to

Evaluation targets resources, not frameworks. The catalog already records
`asset_types` on all 2031 requirements — `iam_role`, `data_store`, `ai_model`,
`audit_log`, `cloud_resource` and 15 more — and a safeguard carries the union of
what its members apply to. `safeguards_for_asset_type("iam_role")` returns the
11 safeguards that bear on IAM roles.

Without that a safeguard cannot be pointed at anything, which would make the
operated object undeployable. The validator rejects a safeguard with no asset
types, and a test asserts each one still matches its members rather than
drifting as curation moves.

## The real ceiling is the catalog, not the curation

90 of 2031 titles still contain identifier-only or boilerplate descriptions,
all ISO 27001 Annex A entries. ISO text is licensed: those need short internal
summaries or licensed access, and must not be copied into this public
repository. The NIST AI RMF titles now use the official subcategory statements
from the pinned NIST AI 100-1 PDF (prior formulaic titles remain in control
history).

NIST SP 800-53 mappings that duplicate a human-reviewed FedRAMP Moderate
mapping inherit that review, because a FedRAMP Moderate control is the 800-53
control of the same identifier. Each inherited mapping records
`review_basis.inherited_from`, and a test keeps the two in lockstep.

The CSF 2.0 catalog now uses the 106 identifiers and outcomes from the pinned
[NIST publication](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf).
Subcategory numbers are not consecutive. The previous generator produced 13
invalid identifiers and omitted 13 official ones despite matching the total
count. Those prior definitions remain in control history; they are not silently
remapped to different outcomes. The new source reconciliation is proposed and
does not claim expert review or full compliance automation.

## Review and evaluation boundaries

`security-lakehouse frameworks review-queue` lists proposed mappings, with
framework and risk-domain filters and source references. The
`get_mapping_review_queue` MCP tool exposes the same review ledger. A reviewer
must confirm semantic equivalence; source provenance alone does not do so.
Your organization records that confirmation, or a rejection, per tenant; see
[Mapping review](MAPPING_REVIEW.md).

Safeguard rules are executable, but the current assessment pipeline still
operates framework controls. Mapped coverage is not the number of safeguards
evaluated on a live environment. Integrating safeguard evaluation into the
pipeline and deriving requirement results from reviewed mappings remains work
to complete. The framework-equivalence overlay also remains a separate source
until that transition is validated.

## Schema

`controls/safeguards.json`, `schema: trustops.safeguards.v1`.

| Field                        | Meaning                                                                        |
| ---------------------------- | ------------------------------------------------------------------------------ |
| `safeguard_id`               | `SG-<RISKDOMAIN>-<NNN>`, stable                                                |
| `title`                      | What the safeguard does                                                        |
| `risk_domain`                | Shared taxonomy with the control catalog                                       |
| `objective`                  | Why these requirements are genuinely the same thing                            |
| `evidence_requirement`       | The single statement this safeguard proves                                     |
| `evaluation_rule`            | The single test                                                                |
| `owner`, `frequency`         | Who operates it, how often                                                     |
| `satisfies[]`                | `control_id`, `framework_id`, `role` (`primary`/`equivalent`), `review_status` |
| `mapping_source`             | Optional source name, HTTPS URL, SHA-256, and exact locator for a crosswalk    |
| `satisfies[].mapping_source` | Per-mapping provenance; overrides safeguard-level provenance in review output  |

Exactly one member carries `role: primary` — the requirement whose wording the
safeguard is drafted against. Every `control_id` must exist in the catalog; the
validator rejects claimed coverage that does not resolve. When a safeguard has
multiple source locators, provenance belongs on each mapping. The review queue
uses that member-level source first and falls back to the safeguard-level source.
