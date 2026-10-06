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
