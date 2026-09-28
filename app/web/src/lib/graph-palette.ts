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

/** A translucent wash of a (possibly var()) colour for chips and swatches. */
export function tint(color: string, percent = 12) {
  return `color-mix(in srgb, ${color} ${percent}%, transparent)`;
}
