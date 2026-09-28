/**
 * Neutral framework visual identity (marks + accents).
 * Not official logos — see docs/THIRD_PARTY_ASSETS.md.
 */

export type FrameworkVisual = {
  label: string;
  mark: string;
  accent: string;
  bg: string;
  ring: string;
  gradient: string;
  /** Lucide icon name key for FrameworkMark */
  icon: FrameworkIconKey;
  /** Approved framework artwork served from the self-hosted console. */
  artwork?: string;
  attribution?: string;
  /** Project-owned compact identity, not a certification seal. */
  badge?: string;
};

export type FrameworkIconKey =
  | "shield"
  | "brain"
  | "lock"
  | "sparkles"
  | "heart-pulse"
  | "credit-card"
  | "scale"
  | "bot"
  | "cloud"
  | "landmark"
  | "layers";

export const FRAMEWORK_VISUALS: Record<string, FrameworkVisual> = {
  soc2: {
    badge: "/console/frameworks/badges/soc2.svg",
    label: "SOC 2® Trust Services Criteria",
    mark: "SOC",
    accent: "#2563eb",
    bg: "#eff6ff",
    ring: "#bfdbfe",
    gradient: "linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)",
    icon: "shield",
  },
  "nist-ai-rmf": {
    badge: "/console/frameworks/badges/nist-ai-rmf.svg",
    label: "NIST AI Risk Management Framework 1.0",
    mark: "AI",
    accent: "#7c3aed",
    bg: "#f5f3ff",
    ring: "#ddd6fe",
    gradient: "linear-gradient(135deg, #8b5cf6 0%, #6d28d9 100%)",
    icon: "brain",
    artwork: "/console/frameworks/nist-ai-rmf.png",
    attribution: "N. Hanacek/NIST",
  },
  "iso-27001-2022": {
    badge: "/console/frameworks/badges/iso.svg",
    label: "ISO/IEC 27001:2022",
    mark: "ISO",
    accent: "#0891b2",
    bg: "#ecfeff",
    ring: "#a5f3fc",
    gradient: "linear-gradient(135deg, #06b6d4 0%, #0e7490 100%)",
    icon: "lock",
  },
  "iso-42001-2023": {
    badge: "/console/frameworks/badges/iso.svg",
    label: "ISO/IEC 42001:2023",
    mark: "AIMS",
    accent: "#0f766e",
    bg: "#f0fdfa",
    ring: "#99f6e4",
    gradient: "linear-gradient(135deg, #14b8a6 0%, #0f766e 100%)",
    icon: "sparkles",
  },
  "fedramp-moderate": {
    label: "FedRAMP",
    mark: "FR",
    accent: "#1e40af",
    bg: "#dbeafe",
    ring: "#93c5fd",
    gradient: "linear-gradient(135deg, #1d4ed8 0%, #1e3a8a 100%)",
    icon: "landmark",
  },
  "nist-800-53-rev5": {
    label: "NIST SP 800-53 Rev 5",
    mark: "800-53",
    accent: "#1e3a8a",
    bg: "#e0e7ff",
    ring: "#a5b4fc",
    gradient: "linear-gradient(135deg, #3730a3 0%, #1e3a8a 100%)",
    icon: "landmark",
  },
  "nist-800-171-rev3": {
    label: "NIST SP 800-171 Rev 3",
    mark: "800-171",
    accent: "#1e3a8a",
    bg: "#e0e7ff",
    ring: "#a5b4fc",
    gradient: "linear-gradient(135deg, #3730a3 0%, #1e3a8a 100%)",
    icon: "lock",
  },
  "nist-rmf-800-37r2": {
    label: "NIST RMF (SP 800-37 Rev 2)",
    mark: "RMF",
    accent: "#155e75",
    bg: "#ecfeff",
    ring: "#67e8f9",
    gradient: "linear-gradient(135deg, #0e7490 0%, #155e75 100%)",
    icon: "layers",
  },
  cis_aws: {
    badge: "/console/frameworks/badges/cis.svg",
    label: "CIS AWS",
    mark: "CIS",
    accent: "#ea580c",
    bg: "#fff7ed",
    ring: "#fed7aa",
    gradient: "linear-gradient(135deg, #f97316 0%, #c2410c 100%)",
    icon: "cloud",
  },
  "cis-controls-v8.1": {
    badge: "/console/frameworks/badges/cis.svg",
    label: "CIS Controls v8.1",
    mark: "CIS",
    accent: "#ea580c",
    bg: "#fff7ed",
    ring: "#fed7aa",
    gradient: "linear-gradient(135deg, #f97316 0%, #c2410c 100%)",
    icon: "shield",
  },
  "hipaa-security-rule": {
    label: "HIPAA",
    mark: "HHS",
    accent: "#059669",
    bg: "#ecfdf5",
    ring: "#a7f3d0",
    gradient: "linear-gradient(135deg, #10b981 0%, #047857 100%)",
    icon: "heart-pulse",
  },
  "pci-dss-v4": {
    label: "PCI DSS",
    mark: "PCI",
    accent: "#d97706",
    bg: "#fffbeb",
    ring: "#fde68a",
    gradient: "linear-gradient(135deg, #f59e0b 0%, #b45309 100%)",
    icon: "credit-card",
  },
  "gdpr-2016-679": {
    badge: "/console/frameworks/badges/eu-ai-act.svg",
    label: "GDPR",
    mark: "EU",
    accent: "#4338ca",
    bg: "#eef2ff",
    ring: "#c7d2fe",
    gradient: "linear-gradient(135deg, #6366f1 0%, #3730a3 100%)",
    icon: "scale",
  },
  "nis2-2022-2555": {
    badge: "/console/frameworks/badges/eu-ai-act.svg",
    label: "NIS2 Directive",
    mark: "NIS2",
    accent: "#4338ca",
    bg: "#eef2ff",
    ring: "#c7d2fe",
    gradient: "linear-gradient(135deg, #6366f1 0%, #3730a3 100%)",
    icon: "shield",
  },
  "dora-2022-2554": {
    badge: "/console/frameworks/badges/eu-ai-act.svg",
    label: "DORA",
    mark: "DORA",
    accent: "#4338ca",
    bg: "#eef2ff",
    ring: "#c7d2fe",
    gradient: "linear-gradient(135deg, #6366f1 0%, #3730a3 100%)",
    icon: "landmark",
  },
  "eu-ai-act-2024-1689": {
    badge: "/console/frameworks/badges/eu-ai-act.svg",
    label: "EU AI Act",
    mark: "EU AI",
    accent: "#be123c",
    bg: "#fff1f2",
    ring: "#fecdd3",
    gradient: "linear-gradient(135deg, #e11d48 0%, #9f1239 100%)",
    icon: "bot",
  },
  "nist-csf-2.0": {
    badge: "/console/frameworks/badges/nist-csf.svg",
    label: "NIST Cybersecurity Framework (CSF) 2.0",
    mark: "CSF",
    accent: "#0f766e",
    bg: "#f0fdfa",
    ring: "#99f6e4",
    gradient: "linear-gradient(135deg, #14b8a6 0%, #0f766e 100%)",
    icon: "shield",
    artwork: "/console/frameworks/nist-csf-2.0.png",
    attribution: "NIST/Natasha Hanacek",
  },
  "cmmc-2-level2": {
    badge: "/console/frameworks/badges/cmmc.svg",
    label: "CMMC 2.0 Level 2",
    mark: "CMMC",
    accent: "#1d4ed8",
    bg: "#eff6ff",
    ring: "#bfdbfe",
    gradient: "linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)",
    icon: "shield",
  },
  "iso-27017-2015": {
    badge: "/console/frameworks/badges/iso.svg",
    label: "ISO/IEC 27017:2015",
    mark: "27017",
    accent: "#0369a1",
    bg: "#f0f9ff",
    ring: "#bae6fd",
    gradient: "linear-gradient(135deg, #0ea5e9 0%, #0369a1 100%)",
    icon: "cloud",
  },
  "iso-27701-2019": {
    badge: "/console/frameworks/badges/iso.svg",
    label: "ISO/IEC 27701:2019",
    mark: "27701",
    accent: "#6d28d9",
    bg: "#f5f3ff",
    ring: "#ddd6fe",
    gradient: "linear-gradient(135deg, #8b5cf6 0%, #6d28d9 100%)",
    icon: "lock",
  },
  "iso-27701-2025": {
    badge: "/console/frameworks/badges/iso.svg",
    label: "ISO/IEC 27701:2025",
    mark: "27701",
    accent: "#6d28d9",
    bg: "#f5f3ff",
    ring: "#ddd6fe",
    gradient: "linear-gradient(135deg, #8b5cf6 0%, #6d28d9 100%)",
    icon: "lock",
  },
  soc1: {
    label: "SOC 1®",
    mark: "SOC 1",
    accent: "#1d4ed8",
    bg: "#eff6ff",
    ring: "#bfdbfe",
    gradient: "linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)",
    icon: "shield",
  },
};

const NAME_TO_ID: Record<string, string> = {
  "SOC 2": "soc2",
  "SOC 2 Trust Services Criteria": "soc2",
  "NIST AI RMF": "nist-ai-rmf",
  "NIST AI Risk Management Framework": "nist-ai-rmf",
  "ISO 27001": "iso-27001-2022",
  "ISO 27001:2022": "iso-27001-2022",
  "ISO 42001": "iso-42001-2023",
  "ISO 42001:2023": "iso-42001-2023",
  FedRAMP: "fedramp-moderate",
  "NIST SP 800-53 Rev 5": "nist-800-53-rev5",
  "NIST SP 800-53": "nist-800-53-rev5",
  "NIST RMF": "nist-rmf-800-37r2",
  "NIST SP 800-171 Rev 3": "nist-800-171-rev3",
  "NIS2 Directive": "nis2-2022-2555",
  NIS2: "nis2-2022-2555",
  DORA: "dora-2022-2554",
  "FedRAMP Moderate": "fedramp-moderate",
  "CIS AWS Foundations Benchmark": "cis_aws",
  "CIS AWS": "cis_aws",
  "CIS Controls": "cis-controls-v8.1",
  "CIS Critical Security Controls v8.1": "cis-controls-v8.1",
  HIPAA: "hipaa-security-rule",
  "PCI DSS": "pci-dss-v4",
  GDPR: "gdpr-2016-679",
  "EU AI Act": "eu-ai-act-2024-1689",
  "NIST CSF 2.0": "nist-csf-2.0",
  "NIST Cybersecurity Framework (CSF) 2.0": "nist-csf-2.0",
  "CMMC 2.0 Level 2": "cmmc-2-level2",
  "ISO/IEC 27017:2015": "iso-27017-2015",
  "ISO/IEC 27701:2019": "iso-27701-2019",
  "ISO/IEC 27701:2025": "iso-27701-2025",
  "ISO 27701:2025": "iso-27701-2025",
  "SOC 1": "soc1",
  "SOC 1®": "soc1",
};

export function resolveFrameworkId(
  frameworkIdOrName: string | null | undefined,
): string {
  if (!frameworkIdOrName) return "unknown";
  if (FRAMEWORK_VISUALS[frameworkIdOrName]) return frameworkIdOrName;
  return NAME_TO_ID[frameworkIdOrName] ?? frameworkIdOrName.toLowerCase();
}

export function frameworkIdFromControlId(controlId: string): string {
  const id = controlId.toUpperCase();
  if (id.startsWith("SOC2-")) return "soc2";
  if (id.startsWith("NIST-AI-RMF-")) return "nist-ai-rmf";
  if (id.startsWith("ISO27001-")) return "iso-27001-2022";
  if (id.startsWith("ISO42001-")) return "iso-42001-2023";
  if (id.startsWith("FEDRAMP-")) return "fedramp-moderate";
  if (id.startsWith("CIS-AWS-")) return "cis_aws";
  if (id.startsWith("HIPAA-")) return "hipaa-security-rule";
  if (id.startsWith("PCI-")) return "pci-dss-v4";
  if (id.startsWith("GDPR-")) return "gdpr-2016-679";
  if (id.startsWith("EU-AI-ACT-")) return "eu-ai-act-2024-1689";
  if (id.startsWith("NIST-800-171R3-")) return "nist-800-171-rev3";
  if (id.startsWith("NIS2-")) return "nis2-2022-2555";
  if (id.startsWith("DORA-")) return "dora-2022-2554";
  return resolveFrameworkId(controlId.split("-")[0]);
}

export function frameworkVisual(
  frameworkIdOrName: string | null | undefined,
  fallbackLabel?: string,
): FrameworkVisual & { frameworkId: string } {
  const frameworkId = resolveFrameworkId(frameworkIdOrName);
  const known = FRAMEWORK_VISUALS[frameworkId];
  if (known) return { ...known, frameworkId };
  const label = fallbackLabel ?? frameworkIdOrName ?? "Framework";
  return {
    frameworkId,
    label,
    mark: label.slice(0, 4).toUpperCase(),
    accent: "#4f7cff",
    bg: "#eef4ff",
    ring: "#c7d7fe",
    gradient: "linear-gradient(135deg, #4f7cff 0%, #2563eb 100%)",
    icon: "layers",
  };
}
