/** Finding severity → Badge tone. One mapping for every surface. */
export const SEVERITY_TONE: Record<
  string,
  "critical" | "serious" | "attention" | "default"
> = {
  critical: "critical",
  high: "serious",
  medium: "attention",
  low: "default",
  info: "default",
};

export function severityTone(severity: string | null | undefined) {
  return SEVERITY_TONE[(severity ?? "").toLowerCase()] ?? "default";
}
