# TrustOps brand

**TrustOps** is the only customer-facing product name. “Security data lake” describes the architecture; it is not a second brand.

| Use                  | Form                          |
| -------------------- | ----------------------------- |
| Product              | **TrustOps**                  |
| Console              | **TrustOps Console**          |
| Reviewer shares      | **TrustOps Trust Center**     |
| Repository / package | `trustops-security-data-lake` |
| Operator CLI         | `security-lakehouse`          |
| MCP command          | `trustops-mcp`                |

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

The full mark places cloud, identity, AI agent, and activity-log symbols above
three lake waves. These represent assets and their evidence entering a shared,
customer-owned evidence layer. The wordmark remains **TrustOps**.

Use the same approved full mark at every size, including the app shell, favicon,
and MCP icons. Do not substitute the log-only variant. The header uses a 48 px
mark and the sidebar uses 40 px. The lake is part of the identity, not a separate
product name.

| Token           | Value                 |
| --------------- | --------------------- |
| Mark gradient   | `#4f7cff` → `#42dfcf` |
| Mark background | `#0b1b2c`             |
| UI accent       | `#30c7d2`             |
| Ink             | `#101623`             |
| Dark rail       | `#07111e`             |
| Wordmark        | Inter, 800–900        |

Primary assets:

- `docs/images/trustops-mark.svg` — full evidence-lake mark
- `docs/images/trustops-logo.svg` — documentation lockup
- `app/web/src/app/icon.svg` — approved favicon
- `src/security_lakehouse/static/trustops-mark.svg` — approved hosted icon
- `src/security_lakehouse/brand_assets.py` — matching embedded MCP icon
- `app/web/src/components/brand/TrustOpsMark.tsx` — UI mark
- `app/web/src/components/brand/TrustOpsLogo.tsx` — UI lockup
- `app/web/public/og/trustops-share.svg` — social preview

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
