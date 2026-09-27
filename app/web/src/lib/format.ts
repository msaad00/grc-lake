import { BRAND } from "@/lib/brand";

/** "1 record" / "3 records"; pass `pluralWord` for irregular nouns. */
export function plural(count: number, word: string, pluralWord?: string) {
  return `${count} ${count === 1 ? word : (pluralWord ?? `${word}s`)}`;
}

/** Minutes in the unit that reads naturally: 90m, 24h, 7d. */
export function formatMinutes(minutes: number | null | undefined): string {
  if (minutes == null || !Number.isFinite(minutes)) return "—";
  if (minutes >= 2880 && minutes % 1440 === 0) return `${minutes / 1440}d`;
  if (minutes >= 60 && minutes % 60 === 0) return `${minutes / 60}h`;
  if (minutes >= 120) return `${Math.round(minutes / 60)}h`;
  return `${minutes}m`;
}

const RELATIVE_UNITS: Array<[Intl.RelativeTimeFormatUnit, number]> = [
  ["day", 86_400_000],
  ["hour", 3_600_000],
  ["minute", 60_000],
];

/** "in 3 days" / "2 hours ago"; "—" for missing or unparseable input. */
export function formatRelative(
  iso: string | null | undefined,
  now: number = Date.now(),
): string {
  if (!iso) return "—";
  const at = new Date(iso).getTime();
  if (Number.isNaN(at)) return "—";
  const diff = at - now;
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  for (const [unit, ms] of RELATIVE_UNITS) {
    if (Math.abs(diff) >= ms) return rtf.format(Math.round(diff / ms), unit);
  }
  return rtf.format(0, "minute");
}

/** Locale date without time, e.g. "Sep 24, 2026". */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime())
    ? "—"
    : parsed.toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
      });
}

/** Locale date and time to the minute — never raw ISO with microseconds. */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime())
    ? "—"
    : parsed.toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "numeric",
        minute: "2-digit",
      });
}

/** Grouped integer for counts, e.g. 2,021; "—" when unknown. */
export function formatCount(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value)) return "—";
  return new Intl.NumberFormat(undefined).format(value);
}

/** Split an identifier or URI into its readable last segment and the
 * prefix it lives under, e.g. "s3://bucket/a/b.json" → ["b.json", "s3://bucket/a/"]. */
export function splitRef(ref: string | null | undefined): [string, string] {
  if (!ref) return ["—", ""];
  const trimmed = ref.replace(/[/:]+$/, "");
  const cut = Math.max(trimmed.lastIndexOf("/"), trimmed.lastIndexOf(":"));
  if (cut <= 0 || cut === trimmed.length - 1) return [ref, ""];
  return [trimmed.slice(cut + 1), trimmed.slice(0, cut + 1)];
}

/** Link to a repo doc on GitHub, e.g. docsUrl("SERVER_AUTH.md"). */
export function docsUrl(path: string): string {
  return `${BRAND.repoUrl}/blob/main/docs/${path}`;
}
