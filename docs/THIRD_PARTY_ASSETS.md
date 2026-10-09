# Third-Party Asset Policy

GRC Lake does not ship made-up framework logos, imitation certification seals,
regulator marks, or third-party trust badges.

Framework and compliance visuals should use project-owned icons and exact
official names unless an
official public brand or certification asset is added with:

- official source URL
- permitted-use terms or written permission
- required attribution
- file owner and review date

Certification marks must not be shown unless GRC Lake or the displayed company
actually holds that certification and the mark usage terms permit the display.

## Current Asset Registry

| Asset family                                                                                               | Current repo status                                | Public rendering policy                                                                                            |
| ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Framework labels such as SOC 2, ISO/IEC 27001, HIPAA, PCI DSS, GDPR, EU AI Act, NIST AI RMF, ISO/IEC 42001 | Exact names with project-owned icons               | Allowed when they identify framework scope and do not imply certification                                          |
| Official certification seals, regulator marks, and framework logos                                         | Not bundled except approved NIST framework artwork | Do not add until source, usage terms, attribution, owner, and review date are recorded here                        |
| Product logos for integrated tools and cloud providers                                                     | Not bundled by default                             | Prefer neutral source labels unless an integration doc requires the mark and permitted-use terms are recorded here |
| Connector brand logos (AWS, Azure, GCP, GitHub, Okta, Snowflake, Google, Jira, ClickHouse)                 | `connector-brand-logos.ts`                         | Integration tiles — Simple Icons (CC0) for monochrome marks; Google Cloud uses official multi-color brand paths    |
| Identity-provider marks (Okta, Entra ID, Google, SAML, API keys)                                           | Generated in `auth-visuals.ts`                     | Text abbreviations for login/access surfaces — not official IdP logos; see `AuthMark` component                    |

## Approved Official Assets

The following are framework illustrations, not agency logos or certification
seals. NIST does not endorse GRC Lake or its control evaluations.

| Framework                              | Local asset                                  | Official source                                                                 | Terms                                                                         | Attribution          | Integrity                                    |
| -------------------------------------- | -------------------------------------------- | ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | -------------------- | -------------------------------------------- |
| NIST Cybersecurity Framework (CSF) 2.0 | `app/web/public/frameworks/nist-csf-2.0.png` | [NIST image record](https://www.nist.gov/image/nist-cybersecurity-framework-20) | [NIST copyright and disclaimers](https://www.nist.gov/copyrights-disclaimers) | NIST/Natasha Hanacek | SHA-256 in `frameworks/identity-assets.json` |
| NIST AI Risk Management Framework 1.0  | `app/web/public/frameworks/nist-ai-rmf.png`  | [NIST image record](https://www.nist.gov/image/ai-risk-management-framework)    | [NIST copyright and disclaimers](https://www.nist.gov/copyrights-disclaimers) | N. Hanacek/NIST      | SHA-256 in `frameworks/identity-assets.json` |

## Architecture diagram marks

The architecture SVGs in `docs/images/` embed connector/provider brand marks to
identify the integrated products — the same marks already registered under
"Connector brand logos" above:

| Mark                                                      | Source                              | Terms                         | File(s)             | Reviewed   |
| --------------------------------------------------------- | ----------------------------------- | ----------------------------- | ------------------- | ---------- |
| AWS, Microsoft Azure, Okta, GitHub, Snowflake, ClickHouse | Simple Icons (monochrome path data) | CC0 1.0; brand colors applied | `docs/images/*.svg` | 2026-08-13 |
| Google Cloud                                              | Official multi-color brand path     | Nominative use                | `docs/images/*.svg` | 2026-08-13 |

Marks identify the named products only and imply no endorsement by, or
certification from, those vendors.

The reviewed decision for every registered framework is recorded in
`frameworks/identity-assets.json`. ISO, AICPA SOC, CIS, FedRAMP, PCI SSC, HHS,
and EU institutional artwork is not bundled because its terms do not permit
generic OSS product use or because no official framework logo exists.

## Compact framework identities

`app/web/public/frameworks/badges/` contains project-owned recognition icons
adapted from Agent-Bom (`ui/public/logos/frameworks/`, Apache-2.0). These use
framework names, simple monograms, a globe, a shield, and a stars motif to
identify scope. They are not official institutional logos or certification
seals. The console uses these at small sizes; the approved NIST illustrations
remain bundled separately. No runtime or repository dependency is introduced.
