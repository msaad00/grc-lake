export function fmtChartDate(iso: string): string {
  const d = new Date(iso);
  return `${d.getMonth() + 1}/${d.getDate()}`;
}

/** Categorical series slots, in their validated order; each theme steps them. */
export const CHART_SERIES = [
  "var(--color-chart-1)",
  "var(--color-chart-2)",
  "var(--color-chart-3)",
  "var(--color-chart-4)",
  "var(--color-chart-5)",
  "var(--color-chart-6)",
  "var(--color-chart-7)",
] as const;

export const FRAMEWORK_LINE_COLORS = CHART_SERIES;

/** Recessive axes: the line recedes, tick text stays readable. */
export const AXIS_PROPS = {
  stroke: "var(--color-line-strong)",
  tick: { fontSize: 11, fill: "var(--color-muted)" },
} as const;

export const GRID_STROKE = "var(--color-line)";

// Recharts paints its tooltip as a white box unless every surface is set.
export const TOOLTIP_STYLE = {
  fontSize: 12,
  borderRadius: 8,
  border: "1px solid var(--color-line)",
  background: "var(--color-surface)",
  color: "var(--color-ink)",
} as const;

export const TOOLTIP_LABEL_STYLE = {
  color: "var(--color-ink)",
  fontWeight: 600,
} as const;

export const TOOLTIP_CURSOR = { stroke: "var(--color-line-strong)" } as const;
