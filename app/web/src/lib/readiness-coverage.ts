import type { FrameworkPosture, FrameworkView } from "./api/types";
import { resolveFrameworkId } from "./framework-visuals";

export const MIN_READINESS_COVERAGE = 0.5;

export type ReadinessCoverage = {
  assessed: number;
  total: number | null;
  sufficient: boolean;
};

export function readinessCoverage(
  evaluated: number | null | undefined,
  catalogTotal: number | null | undefined,
): ReadinessCoverage {
  const assessed =
    typeof evaluated === "number" && Number.isFinite(evaluated)
      ? Math.max(0, evaluated)
      : 0;
  const total =
    typeof catalogTotal === "number" &&
    Number.isFinite(catalogTotal) &&
    catalogTotal > 0
      ? catalogTotal
      : null;
  return {
    assessed,
    total,
    sufficient: total !== null && assessed / total >= MIN_READINESS_COVERAGE,
  };
}

const POSTURE_FRAMEWORK_IDS: Record<string, string> = {
  "SOC 2": "soc2",
  "NIST AI RMF": "nist-ai-rmf",
  "ISO 27001": "iso-27001-2022",
  "ISO 42001": "iso-42001-2023",
  HIPAA: "hipaa-security-rule",
  "PCI DSS": "pci-dss-v4",
  GDPR: "gdpr-2016-679",
  "EU AI Act": "eu-ai-act-2024-1689",
  FedRAMP: "fedramp-moderate",
  "CIS AWS": "cis_aws",
};

/** Catalog id for a posture row's framework display name. */
export function postureFrameworkId(label: string): string {
  return resolveFrameworkId(POSTURE_FRAMEWORK_IDS[label] ?? label);
}

type PostureRow = Pick<
  FrameworkPosture,
  "framework" | "control_count" | "not_evaluated_control_count"
>;
type CatalogRow = Pick<FrameworkView, "framework_id" | "control_count">;

/** Assessed controls against one framework's catalogued requirements. */
export function frameworkCoverage(
  framework: PostureRow,
  catalogById: Map<string, CatalogRow>,
): ReadinessCoverage {
  const total =
    catalogById.get(postureFrameworkId(framework.framework))?.control_count ??
    null;
  // A control with evidence but no verdict was observed, not assessed.
  const assessed =
    framework.control_count - (framework.not_evaluated_control_count ?? 0);
  return readinessCoverage(assessed, total);
}

export type WorkspaceCoverage = {
  /** Assessed controls in packs with a known catalog size. */
  assessed: number;
  /** Catalogued requirements across those packs. */
  total: number;
  /** Whole percent, or null when no evaluated pack has a catalog size. */
  percent: number | null;
  /** Evaluated packs left out because their catalog size is unknown. */
  unknownPacks: number;
};

/**
 * How much of the catalogued requirement set in the evaluated framework packs
 * has a verdict. A different question from the assessment score, which is the
 * pass share of what was assessed.
 */
export function workspaceCoverage(
  frameworks: PostureRow[],
  catalog: CatalogRow[],
): WorkspaceCoverage {
  const catalogById = new Map(catalog.map((row) => [row.framework_id, row]));
  let assessed = 0;
  let total = 0;
  let unknownPacks = 0;
  for (const framework of frameworks) {
    const coverage = frameworkCoverage(framework, catalogById);
    if (coverage.total === null) {
      unknownPacks += 1;
      continue;
    }
    assessed += Math.min(coverage.assessed, coverage.total);
    total += coverage.total;
  }
  return {
    assessed,
    total,
    percent: total > 0 ? Math.round((assessed / total) * 100) : null,
    unknownPacks,
  };
}
