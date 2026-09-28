import { MAPPING_REVIEW_GLOSSARY } from "@/lib/console-copy";

/** Labels that sentence case alone would get wrong. */
const OVERRIDES: Record<string, string> = {
  ...Object.fromEntries(
    Object.entries(MAPPING_REVIEW_GLOSSARY).map(([key, entry]) => [
      key,
      entry.label,
    ]),
  ),
  sla: "SLA",
  api: "API",
  ai: "AI",
  mfa: "MFA",
  ok: "OK",
  na: "N/A",
};

/**
 * Display text for a status, severity, or state enum ("in_progress" →
 * "In progress"). Badges and chips render through this, never the raw value.
 */
export function displayLabel(value: string | null | undefined): string {
  if (!value) return "";
  const key = value.trim().toLowerCase();
  if (OVERRIDES[key]) return OVERRIDES[key];
  const words = key.split(/[_\s-]+/).filter(Boolean);
  if (!words.length) return "";
  return words
    .map((word, index) => {
      const fixed = OVERRIDES[word];
      if (fixed) return fixed;
      return index === 0 ? word[0].toUpperCase() + word.slice(1) : word;
    })
    .join(" ");
}
