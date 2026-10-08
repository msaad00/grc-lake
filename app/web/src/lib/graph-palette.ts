import type { GraphNodeKind } from "@/lib/api/types";

/**
 * Identity colours for the four compliance-graph layers. They resolve to
 * theme tokens (validated categorical slots) so light and dark each get their
 * own step; node kind labels and the legend carry identity too.
 */
export const GRAPH_LAYER = {
  framework: "var(--color-graph-1)",
  control: "var(--color-graph-2)",
  evidence_type: "var(--color-graph-3)",
  asset: "var(--color-graph-4)",
} as const;

/**
 * Every graph node kind resolves to a theme token. Repository kinds reuse the
 * chart series and status slots; the kind label and icon carry identity where
 * two kinds share a hue.
 */
export const GRAPH_KIND_COLOR = {
  ...GRAPH_LAYER,
  repository: "var(--color-chart-1)",
  directory: "var(--color-line-strong)",
  language: "var(--color-chart-3)",
  evidence_signal: "var(--color-chart-4)",
  governance_signal: "var(--color-info)",
  signal_gap: "var(--color-danger)",
  workflow: "var(--color-chart-7)",
  dependency_manifest: "var(--color-chart-2)",
  ownership_file: "var(--color-chart-5)",
  security_file: "var(--color-success)",
  file: "var(--color-muted)",
  principal: "var(--color-chart-5)",
  team: "var(--color-chart-7)",
  review_rule: "var(--color-chart-6)",
  status_check: "var(--color-success)",
  workflow_permission: "var(--color-serious)",
  evidence: "var(--color-neutral-fg)",
} as const satisfies Record<GraphNodeKind, string>;

/** A translucent wash of a (possibly var()) colour for chips and swatches. */
export function tint(color: string, percent = 12) {
  return `color-mix(in srgb, ${color} ${percent}%, transparent)`;
}
