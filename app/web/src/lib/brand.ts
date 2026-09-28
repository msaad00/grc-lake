/** TrustOps product identity — single source for UI copy and metadata. */

export const BRAND = {
  /** Customer-facing product name. */
  name: "TrustOps",
  /** Human console surface. */
  consoleName: "TrustOps Console",
  /** Category line used in README and marketing-adjacent docs. */
  category: "Open, self-hosted GRC for cloud and AI",
  /** One-line mission for meta tags and share cards. */
  tagline:
    "Customer-owned evidence. Deterministic controls. Continuous assurance.",
  /** Headless-first differentiator. */
  surfaces: "API · CLI · MCP · CI · Console",
  /** Short description for Open Graph / npm / package manifests. */
  description:
    "Open, self-hosted GRC for cloud and AI, built for humans and agents — customer-owned evidence, deterministic controls, and reviewable assessments.",
  /** Public trust-center header subtitle. */
  trustShareTitle: "TrustOps Trust Center",
  /** Repo / PyPI technical name (not customer-facing). */
  packageName: "trustops-security-data-lake",
  /** CLI command (operator surface, not product rename). */
  cliCommand: "security-lakehouse",
  version: "0.2.19",
  colors: {
    blue: "#4f7cff",
    cyan: "#30c7d2",
    ink: "#101623",
  },
  repoUrl: "https://github.com/msaad00/trustops-security-data-lake",
  mcpServerName: "trustops",
  mcpCommand: "trustops-mcp",
  /** Dashboard home eyebrow (feature area, not product name). */
  homeEyebrow: "Home",
  /** Short label under the wordmark in chrome. */
  consoleSubtitle: "Console",
} as const;
