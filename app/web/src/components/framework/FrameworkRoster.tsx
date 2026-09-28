import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { FrameworkBadge } from "@/components/framework/FrameworkBadge";
import type {
  FrameworkCoverageRow,
  FrameworkReadiness,
  FrameworkView,
} from "@/lib/api/types";
import { formatCount } from "@/lib/format";
import {
  splitFrameworkPacks,
  stubCountLabel,
  stubStatusLabel,
} from "@/lib/framework-packs";

interface Props {
  frameworks: FrameworkView[];
  coverage: FrameworkCoverageRow[];
  readiness: FrameworkReadiness[];
}

function FrameworkLine({
  framework,
  coverage,
  readiness,
  stubLabel,
  showStatus = true,
}: {
  framework: FrameworkView;
  coverage?: FrameworkCoverageRow;
  readiness?: FrameworkReadiness;
  /** Set for registry stubs (planned or superseded); replaces the counts. */
  stubLabel?: string;
  /** Hidden when every tracked row shares one status. */
  showStatus?: boolean;
}) {
  const notEvaluated = Boolean(stubLabel);
  const mapped =
    coverage?.evaluatable_requirement_count ??
    framework.implemented_control_count;
  const total = coverage?.seeded_control_count ?? framework.control_count;
  const attestable = coverage?.attestable_requirement_count ?? 0;
  const orgReviewed = coverage?.org_reviewed_requirement_count ?? 0;

  return (
    <li className="flex min-w-0 items-center gap-3 border-b border-line py-3.5 last:border-b-0">
      <FrameworkBadge
        frameworkId={framework.framework_id}
        fallbackLabel={framework.name}
        size={44}
        variant="mark-only"
      />
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-semibold text-ink">
          {framework.name}
        </div>
        <div className="mt-0.5 truncate text-xs font-medium leading-5 text-muted">
          {notEvaluated
            ? stubLabel
            : `${formatCount(mapped)}/${formatCount(total)} controls mapped · ${formatCount(attestable)} reviewed${orgReviewed ? ` (${formatCount(orgReviewed)} by your org)` : ""}`}
        </div>
      </div>
      {notEvaluated ? (
        <Badge tone="default">
          {framework.superseded_by ? "Superseded" : "Planned"}
        </Badge>
      ) : showStatus ? (
        <Badge tone={readiness?.is_ready ? "ready" : "attention"}>
          {readiness?.is_ready ? "Ready" : "Needs attention"}
        </Badge>
      ) : (
        <span
          className="shrink-0 text-xs font-semibold tabular-nums text-ink"
          title="Requirements with a reviewed mapping"
        >
          {total ? Math.round((attestable / total) * 100) : 0}% reviewed
        </span>
      )}
    </li>
  );
}

export function FrameworkRoster({ frameworks, coverage, readiness }: Props) {
  const coverageById = new Map(coverage.map((row) => [row.framework_id, row]));
  const readinessById = new Map(
    readiness.map((row) => [row.framework_id, row]),
  );
  const { packs: evaluated, stubs: notEvaluated } =
    splitFrameworkPacks(frameworks);
  const names = new Map(frameworks.map((row) => [row.framework_id, row.name]));
  const readyStates = new Set(
    evaluated.map((row) =>
      Boolean(readinessById.get(row.framework_id)?.is_ready),
    ),
  );
  // One status on every row is noise; show each row's review progress instead.
  const sharedStatus = evaluated.length > 1 && readyStates.size === 1;

  return (
    <Card aria-label="Framework roster" className="overflow-hidden">
      <div className="flex flex-wrap items-end justify-between gap-3 border-b border-line px-4 py-3">
        <div>
          <h2 className="text-lg font-semibold text-ink">Framework roster</h2>
          <p className="mt-0.5 max-w-3xl text-xs leading-5 text-muted">
            Mapping and review status by framework.
          </p>
        </div>
        <div className="text-right text-xs font-semibold text-muted">
          <div>
            {evaluated.length} packs
            {notEvaluated.length
              ? ` · ${stubCountLabel(notEvaluated.length)}`
              : ""}
          </div>
          <div className="mt-0.5 font-normal">
            {sharedStatus
              ? `All packs: ${readyStates.has(true) ? "Ready" : "Needs attention"}`
              : "Catalog and mapping status"}
          </div>
        </div>
      </div>
      <div className="grid gap-5 px-4 pb-3 md:grid-cols-2 md:gap-6">
        <section aria-labelledby="framework-roster-tracked">
          <h3
            id="framework-roster-tracked"
            className="pt-3 text-[11px] font-semibold uppercase tracking-wide text-muted"
          >
            Readiness tracked
          </h3>
          <ul role="list" className="mt-1">
            {evaluated.map((framework) => (
              <FrameworkLine
                key={framework.framework_id}
                framework={framework}
                coverage={coverageById.get(framework.framework_id)}
                readiness={readinessById.get(framework.framework_id)}
                showStatus={!sharedStatus}
              />
            ))}
          </ul>
        </section>
        <section aria-labelledby="framework-roster-unavailable">
          <h3
            id="framework-roster-unavailable"
            className="pt-3 text-[11px] font-semibold uppercase tracking-wide text-muted"
          >
            Planned or superseded
          </h3>
          <ul role="list" className="mt-1">
            {notEvaluated.length > 0 ? (
              notEvaluated.map((framework) => (
                <FrameworkLine
                  key={framework.framework_id}
                  framework={framework}
                  coverage={coverageById.get(framework.framework_id)}
                  readiness={readinessById.get(framework.framework_id)}
                  stubLabel={stubStatusLabel(framework, names)}
                />
              ))
            ) : (
              <li className="py-3 text-xs text-muted">
                Every registry entry has catalogued requirements.
              </li>
            )}
          </ul>
        </section>
      </div>
    </Card>
  );
}
