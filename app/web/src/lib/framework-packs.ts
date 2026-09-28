import type { FrameworkPackState } from "@/lib/api/types";

type PackEntry = {
  pack_state?: FrameworkPackState;
  control_count?: number;
  seeded_control_count?: number;
  superseded_by?: string | null;
};

/**
 * A registry entry with seeded requirements is a framework pack; one without
 * (a planned pack or a superseded edition) is a stub. The API sends
 * `pack_state` from `framework_pack_state()`; the fallback mirrors that rule.
 */
export function packState(entry: PackEntry): FrameworkPackState {
  if (entry.pack_state) return entry.pack_state;
  if ((entry.control_count ?? entry.seeded_control_count ?? 0) > 0)
    return "seeded";
  return entry.superseded_by ? "superseded" : "planned";
}

export function splitFrameworkPacks<T extends PackEntry>(
  entries: readonly T[],
) {
  const packs: T[] = [];
  const stubs: T[] = [];
  for (const entry of entries)
    (packState(entry) === "seeded" ? packs : stubs).push(entry);
  return { packs, stubs };
}

/** "2 planned or superseded", or "" when every entry is a pack. */
export function stubCountLabel(stubCount: number): string {
  return stubCount > 0 ? `${stubCount} planned or superseded` : "";
}

/** Status line for a stub, naming the successor edition when superseded. */
export function stubStatusLabel(
  entry: PackEntry,
  names: ReadonlyMap<string, string> = new Map(),
): string {
  if (packState(entry) === "superseded" && entry.superseded_by)
    return `Superseded by ${names.get(entry.superseded_by) ?? entry.superseded_by}`;
  return "Planned · no requirements catalogued";
}
