"use client";

import Link from "next/link";
import { useCcfCoverage } from "@/lib/api/hooks";
import type { CcfCategoryRow, CcfFamilyRow } from "@/lib/api/types";
import { CollapsibleCard } from "@/components/ui/collapsible-card";
import { ControlFamilyIcon } from "@/components/framework/ControlFamilyIcon";
import { MAPPING_REVIEW_GLOSSARY } from "@/lib/console-copy";

function plural(count: number, noun: string, many = `${noun}s`) {
  return `${count.toLocaleString()} ${count === 1 ? noun : many}`;
}

function FamilyRow({ family }: { family: CcfFamilyRow }) {
  return (
    <details
      className="min-w-0 border-b border-line last:border-b-0"
      data-family={family.family_id}
    >
      <summary className="flex cursor-pointer items-center gap-3 rounded py-2.5 focus-visible:outline focus-visible:outline-2 focus-visible:outline-brand">
        <ControlFamilyIcon domain={family.family_id} />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-semibold text-ink">
            {family.label}
          </span>
          <span className="block text-xs text-muted">
            {plural(family.safeguard_count, "safeguard")} ·{" "}
            {plural(family.mapped_requirement_count, "requirement")}
          </span>
        </span>
        <span className="shrink-0 text-right text-xs tabular-nums text-muted">
          {family.reviewed_mapping_count.toLocaleString()}{" "}
          <span className="hidden sm:inline">reviewed</span>
          <span className="sm:hidden">rev.</span>
          {" / "}
          {family.proposed_mapping_count.toLocaleString()}{" "}
          <span className="hidden sm:inline">proposed</span>
          <span className="sm:hidden">prop.</span>
        </span>
      </summary>
      <div className="space-y-2 pb-3 pl-12 text-xs text-muted">
        <p className="text-sm text-ink">{family.description}</p>
        <p>
          Maps to {plural(family.framework_count, "framework")}
          {family.nist_800_53_families.length
            ? ` · NIST SP 800-53 ${family.nist_800_53_families.join(", ")}`
            : ""}
          {family.cis_controls.length
            ? ` · CIS Controls ${family.cis_controls.join(", ")}`
            : ""}
        </p>
        <Link
          href={`/mapping-review/?family=${encodeURIComponent(family.family_id)}`}
          className="ui-link inline-block"
        >
          Review {family.label} mappings
        </Link>
      </div>
    </details>
  );
}

function CategorySection({
  category,
  families,
}: {
  category: CcfCategoryRow;
  families: CcfFamilyRow[];
}) {
  const headingId = `ccf-category-${category.category_id}`;
  return (
    <section
      aria-labelledby={headingId}
      className="min-w-0"
      data-category={category.category_id}
    >
      <div className="flex items-baseline justify-between gap-3 border-b border-line-strong/60 pb-1.5 pt-3">
        <h3 id={headingId} className="text-sm font-semibold text-ink">
          {category.label}
        </h3>
        <span className="shrink-0 text-xs tabular-nums text-muted">
          {plural(category.family_count, "family", "families")} ·{" "}
          {plural(category.safeguard_count, "safeguard")}
        </span>
      </div>
      {families.map((family) => (
        <FamilyRow key={family.family_id} family={family} />
      ))}
    </section>
  );
}

export function ControlFamilies({ embedded = false }: { embedded?: boolean }) {
  const query = useCcfCoverage();
  const categories = query.data?.categories ?? [];
  const families = query.data?.families ?? [];
  const byId = new Map(families.map((row) => [row.family_id, row]));
  const safeguards = categories.reduce(
    (sum, row) => sum + row.safeguard_count,
    0,
  );
  return (
    <CollapsibleCard
      embedded={embedded}
      title="Control families"
      storageKey="dashboard-control-families"
      defaultOpen={false}
      description={`${categories.length} categories · ${families.length} families · ${safeguards} safeguards`}
      contentClassName="max-h-[440px] overflow-y-auto px-5 py-2"
    >
      {query.isError ? (
        <p className="py-3 text-sm text-muted">
          Unable to load control families.
        </p>
      ) : query.isPending ? (
        <p className="py-3 text-sm text-muted">Loading control families…</p>
      ) : (
        <>
          <p className="pb-1 text-xs text-muted">
            Mapping counts read reviewed / proposed.{" "}
            {MAPPING_REVIEW_GLOSSARY.proposed.label}:{" "}
            {MAPPING_REVIEW_GLOSSARY.proposed.definition}
          </p>
          <div className="grid gap-x-8 2xl:grid-cols-2">
            {categories.map((category) => (
              <CategorySection
                key={category.category_id}
                category={category}
                families={category.family_ids
                  .map((id) => byId.get(id))
                  .filter((row): row is CcfFamilyRow => Boolean(row))}
              />
            ))}
          </div>
        </>
      )}
    </CollapsibleCard>
  );
}
