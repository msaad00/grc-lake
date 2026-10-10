# GRC Lake brand

**GRC Lake** is the only customer-facing product name. “Security data lake” describes the architecture; it is not a second brand.

| Use                  | Form                      |
| -------------------- | ------------------------- |
| Product              | **GRC Lake**              |
| Console              | **GRC Lake Console**      |
| Reviewer shares      | **GRC Lake Trust Center** |
| Repository / package | `grc-lake`                |
| Operator CLI         | `grc-lake`                |
| MCP command          | `grc-lake-mcp`            |

The exact `koda-ai-studio` identifier is permitted for GitHub/GHCR ownership and
publisher configuration. It is an organization identifier, not a product name
or visual wordmark.

Do not introduce alternate product names. Do not use “Workbench,” “Assessment Console,” or “Security Lakehouse” as a customer-facing brand.

## Positioning

- **Descriptor:** open, self-hosted GRC for cloud and AI
- **Direction:** the open-source home for asset visibility and continuous assurance
- **Audience:** built for humans and agents
- **Differentiator:** customer-owned evidence, deterministic controls, one contract across Console · API · CLI · MCP · CI

## Product scope and claims

The product direction connects inventory and visibility to framework evaluation,
posture monitoring, remediation suggestions, assignments, evidence review, and
audit readiness. Inventory should cover cloud assets, identities, AI services,
models, and agents as supported sources expand.

Describe that direction separately from implemented and verified capabilities.
State which sources, asset types, rules, and workflows were actually evaluated;
missing evidence and unsupported checks must remain visible. Framework mappings
are not proof of compliance. Certification support means readiness tracking and
evidence preparation for assessors, not issuing certifications or guaranteeing
an audit outcome. Suggested remediation is distinct from an executed change.

Humans and agents are first-class users of the same evidence and assessment
contracts. Human workflows should support investigation, ownership, and review.
Agent workflows should offer discoverable tools, structured outputs, explicit
errors and completeness, stable identifiers, job status, and retry behavior.
Both must honor tenant boundaries, scoped permissions, and approval requirements;
agent use must not bypass review or turn a suggested fix into an executed change.
Validate these properties per interface before describing them as supported.

Triage should explain business impact using environment, customer exposure,
sensitive data, dependencies, asset criticality, evidence confidence, and ownership.
Production and customer-facing context can raise priority; internal systems may
also be critical. Unknown context must remain unknown. Keep control verdict,
technical severity, and business priority distinct. This is product guidance,
not a claim that every context source or prioritization rule is implemented.

## Visual identity

The full mark combines an open G with three evidence-lake waves. At 40 px and
below, the app uses the waves alone for legibility. The wordmark is **GRC Lake**.
The logo, favicon, social card and embedded MCP icon are generated from the same
canonical SVG in `brand_assets.py` using `tools/render_readme_header.py`.

| Token           | Value                 |
| --------------- | --------------------- |
| Mark gradient   | `#4f7cff` → `#42dfcf` |
| Mark background | `#0b1b2c`             |
| UI accent       | `#30c7d2`             |
| Ink             | `#101623`             |
| Dark rail       | `#07111e`             |
| Wordmark        | Inter, 800–900        |

Primary assets:

- `docs/images/grc-lake-mark.svg` — full evidence-lake mark
- `docs/images/grc-lake-logo.svg` — documentation lockup
- `app/web/src/app/icon.svg` — approved favicon
- `src/security_lakehouse/static/grc-lake-mark.svg` — approved hosted icon
- `src/security_lakehouse/brand_assets.py` — matching embedded MCP icon
- `app/web/src/components/brand/GrcLakeMark.tsx` — UI mark
- `app/web/src/components/brand/GrcLakeLogo.tsx` — UI lockup
- `app/web/public/og/grc-lake-share.svg` — social preview

Do not stretch, rotate, shadow, or recolor the mark. Framework and connector logos follow [THIRD_PARTY_ASSETS.md](THIRD_PARTY_ASSETS.md).

## Voice

- Direct and operational.
- Repository content is public: use sanitized examples and verified claims; keep
  account identifiers, secrets, private commercial terms, and internal strategy out.
- Explain the evidence boundary before the feature list.
- Say what is deterministic, what is model-assisted, and what requires approval.
- Prefer concrete verbs: collect, evaluate, resolve, export.

Brand constants live in `app/web/src/lib/brand.ts`. Layout and component guidance lives in [VISUAL_SYSTEM.md](VISUAL_SYSTEM.md).

## Operational interface copy

Keep positioning and marketing descriptors in the README and product metadata.
Console screens use task names, status, counts, asset context, and actions.
Use “Dashboard”, “Frameworks”, and “Control results”; avoid executive slogans,
architecture explanations, and certification claims in page headings or cards.
Use compact framework identities with full readable names, separate assessment
scores from failing and stale counts, and put detailed mappings behind disclosure.
