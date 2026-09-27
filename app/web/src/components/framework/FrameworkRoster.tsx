import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { FrameworkBadge } from "@/components/framework/FrameworkBadge";
import type {
  FrameworkCoverageRow,
  FrameworkReadiness,
  FrameworkView,
} from "@/lib/api/types";
import { formatCount } from "@/lib/format";

interface Props {
  frameworks: FrameworkView[];
  coverage: FrameworkCoverageRow[];
  readiness: FrameworkReadiness[];
}

function FrameworkLine({
  framework,
  coverage,
  readiness,
  notEvaluated = false,
}: {
  framework: FrameworkView;
  coverage?: FrameworkCoverageRow;
  readiness?: FrameworkReadiness;
  notEvaluated?: boolean;
}) {
  const mapped =
    coverage?.evaluatable_requirement_count ??
    framework.implemented_control_count;
  const total = coverage?.seeded_control_count ?? framework.control_count;
  const attestable = coverage?.attestable_requirement_count ?? 0;

  return (
    <li className="flex min-w-0 items-center gap-3 border-b border-line py-3.5 last:border-b-0">
      <FrameworkBadge
        frameworkId={framework.framework_id}
        fallbackLabel={framework.name}
        size={44}
        variant="mark-only"
      />
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-black text-ink">
          {framework.name}
        </div>
        <div className="mt-0.5 truncate text-xs font-medium leading-5 text-muted">
          {notEvaluated
            ? `Not evaluated · ${total ? `${formatCount(total)} controls in catalog` : "catalog pack pending"}`
            : `${formatCount(mapped)}/${formatCount(total)} controls mapped · ${formatCount(attestable)} fully reviewed`}
        </div>
      </div>
      <Badge
        tone={
          notEvaluated ? "default" : readiness?.is_ready ? "ready" : "attention"
        }
      >
        {notEvaluated
          ? "Not evaluated"
          : readiness?.is_ready
            ? "Ready"
            : "Needs attention"}
      </Badge>
    </li>
  );
}

export function FrameworkRoster({ frameworks, coverage, readiness }: Props) {
  const coverageById = new Map(coverage.map((row) => [row.framework_id, row]));
  const readinessById = new Map(
    readiness.map((row) => [row.framework_id, row]),
  );
  const evaluated = frameworks.filter(
    (framework) =>
      framework.implementation_status !== "planned" &&
      framework.control_count > 0,
  );
  const notEvaluated = frameworks.filter(
    (framework) =>
      framework.implementation_status === "planned" ||
      framework.control_count === 0,
  );

  return (
    <Card aria-label="Framework roster" className="overflow-hidden">
      <div className="flex flex-wrap items-end justify-between gap-3 border-b border-line px-4 py-3">
        <div>
          <h2 className="text-lg font-black text-ink">Framework roster</h2>
          <p className="mt-0.5 max-w-3xl text-xs leading-5 text-muted">
            Mapping and review status by framework.
          </p>
        </div>
        <div className="text-right text-xs font-bold text-muted">
          <div>
            {evaluated.length} tracked · {notEvaluated.length} not evaluated
          </div>
          <div className="mt-0.5 font-normal">Catalog and mapping status</div>
        </div>
      </div>
      <div className="grid gap-5 px-4 pb-3 md:grid-cols-2 md:gap-6">
        <section aria-labelledby="framework-roster-tracked">
          <h3
            id="framework-roster-tracked"
            className="pt-3 text-[10px] font-black uppercase tracking-[0.18em] text-muted"
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
              />
            ))}
          </ul>
        </section>
        <section aria-labelledby="framework-roster-unavailable">
          <h3
            id="framework-roster-unavailable"
            className="pt-3 text-[10px] font-black uppercase tracking-[0.18em] text-muted"
          >
            Not evaluated
          </h3>
          <ul role="list" className="mt-1">
            {notEvaluated.length > 0 ? (
              notEvaluated.map((framework) => (
                <FrameworkLine
                  key={framework.framework_id}
                  framework={framework}
                  coverage={coverageById.get(framework.framework_id)}
                  readiness={readinessById.get(framework.framework_id)}
                  notEvaluated
                />
              ))
            ) : (
              <li className="py-3 text-xs text-muted">
                All registered framework packs have an evaluation surface.
              </li>
            )}
          </ul>
        </section>
      </div>
    </Card>
  );
}
