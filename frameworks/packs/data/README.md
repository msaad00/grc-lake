# Pack source data

Manifest data used by `security-lakehouse frameworks sync-packs`. Every
framework pack's identifiers, titles, and source citation live here as JSON;
`src/security_lakehouse/framework_packs.py` and `limited_packs.py` read them
through `pack_from_manifest()` — see [../../../docs/FRAMEWORK_PACKS.md](../../../docs/FRAMEWORK_PACKS.md#manifest-schema)
for the manifest schema and the "add a new framework" workflow.

| File                             | Pack                |                                           Count |
| -------------------------------- | ------------------- | ----------------------------------------------: |
| `soc2.json`                      | `soc2`              | **61** (33 common criteria + 28 TSC extensions) |
| `nist_ai_rmf.json`               | `nist-ai-rmf`       |                                          **72** |
| `nist_csf_2_core.json`           | `nist-csf-2.0`      |                                         **106** |
| `nist_800_53_rev5_moderate.json` | `fedramp-moderate`  |                                         **287** |
| `nist_800_53_rev5_catalog.json`  | `nist-800-53-rev5`  |                                        **1014** |
| `nist_rmf_800_37r2.json`         | `nist-rmf-800-37r2` |                                          **47** |
| `cis_controls_v8_1.json`         | `cis-controls`      |                                          **18** |
| `cis_aws_v3.json`                | `cis-aws`           |                                          **62** |
| `cmmc_2_level2.json`             | `cmmc-2-level2`     |                                         **110** |
| `iso_27001_2022.json`            | `iso-27001-2022`    |                                          **93** |
| `iso_27017_2015.json`            | `iso-27017-2015`    |                                          **47** |
| `iso_42001_2023.json`            | `iso-42001-2023`    |                                          **38** |
| `iso_27701_2025.json`            | `iso-27701`         |                 **10** (68 Annex A gaps listed) |
| `nist_800_171_rev3.json`         | `nist-800-171-rev3` |                **97** (with Rev 2 predecessors) |
| `nis2_2022_2555.json`            | `nis2`              |                                          **17** |
| `dora_2022_2554.json`            | `dora`              |                                          **99** |
| `gdpr_2016_679.json`             | `gdpr`              |                                          **14** |
| `hipaa_security_rule.json`       | `hipaa`             |                                    see manifest |
| `pci_dss_v4.json`                | `pci-dss`           |                                          **12** |
| `eu_ai_act_2024_1689.json`       | `eu-ai-act`         |                                          **10** |
| `evidence_connector_hints.json`  | all packs           |                                               — |

`nist_csf_2_core.json` is the original manifest precedent for this pattern
(pinned to an official source digest — see `tests/test_csf_source_integrity.py`).
FedRAMP's control identifiers (`nist_800_53_rev5_moderate.json`) come from the
NIST SP 800-53 Rev 5 **Moderate baseline** OSCAL profile
(`NIST_SP-800-53_rev5_MODERATE-baseline_profile.json`); FedRAMP Rev 5 Moderate
authorization selects 323 controls with overlays — the delta ships in a
follow-up pack.

Some files (`cis_aws_v3.json`, `cmmc_2_level2.json`, `iso_27017_2015.json`,
`nist_800_53_rev5_moderate.json`) predate the general manifest schema and use
their own top-level row key (`requirements`/`controls`/`control_ids` instead
of `rows`) — `pack_from_manifest(..., rows_key=...)` reads them as-is so other
direct consumers (e.g. `sprs.py` reads `cmmc_2_level2.json` for SPRS scoring
metadata) are unaffected.

HIPAA catalog rows include standards and selected implementation specifications;
their count is not the statutory count of Security Rule standards. Supported
granular identifiers are retained. Newly reconciled entries cite their eCFR
section and start on their source reconciliation date, without changing earlier
catalog versions. Adding a source identity does not approve a cross-framework
mapping or establish operating effectiveness.
