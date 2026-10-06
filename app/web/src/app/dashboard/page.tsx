"use client";

import {
  useControlTests,
  useFrameworks,
  useIngestionStatus,
  usePosture,
  usePostureStream,
} from "@/lib/api/hooks";
import { DashboardPanel } from "@/components/dashboard/DashboardPanel";
import { AssessmentOverview } from "@/components/dashboard/AssessmentOverview";
import { ControlFamilies } from "@/components/dashboard/ControlFamilies";
import { ReadinessGrid } from "@/components/dashboard/ReadinessGrid";
import { FixNext } from "@/components/dashboard/FixNext";
import { ControlTestTable } from "@/components/dashboard/ControlTestTable";
import { IngestionStatusPanel } from "@/components/dashboard/IngestionStatusPanel";
import { EvalRunsStrip } from "@/components/dashboard/EvalRunsStrip";
import { Badge } from "@/components/ui/badge";
import { CollapsibleCard } from "@/components/ui/collapsible-card";
import { QueryState } from "@/components/QueryState";
import { PageHeader } from "@/components/PageHeader";
import { ROUTE_LABELS } from "@/lib/console-copy";
import { splitFrameworkPacks } from "@/lib/framework-packs";

export default function DashboardPage() {
  const posture = usePosture();
  const tests = useControlTests();
  const ingestion = useIngestionStatus();
  const registeredFrameworks = useFrameworks();
  usePostureStream();
  const data = posture.data;
  const frameworks = data?.frameworks ?? [];
  const { packs: frameworkPacks } = splitFrameworkPacks(
    registeredFrameworks.data ?? [],
  );
  const packCount = registeredFrameworks.data
    ? frameworkPacks.length
    : frameworks.length;
  const ingestionNeedsAttention =
    ingestion.data?.state !== "active" ||
    Boolean(ingestion.data?.recommended_actions?.length) ||
    Boolean(ingestion.data?.scale?.eval_overdue);
  const ingestionDescription = ingestionNeedsAttention
    ? (ingestion.data?.recommended_actions?.[0]?.reason ??
      "Connector health or control eval needs attention")
    : "Source sync health and control eval runs";

  return (
    <div className="page-shell grid gap-5">
      <PageHeader
        title={ROUTE_LABELS["/dashboard"]}
        description="Your evidence, coverage gaps, and next actions in one place."
      />

      <QueryState queries={[posture, ingestion]} label="overview">
        <AssessmentOverview
          assessment={data}
          ingestion={ingestion.data}
          frameworkCount={packCount}
        />

        <div className="grid min-w-0 items-start gap-5 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
          <DashboardPanel
            title="Framework coverage"
            storageKey="dashboard-compliance-panel"
            tabs={[
              {
                label: "Frameworks",
                content: (
                  <ReadinessGrid
                    embedded
                    frameworks={frameworks}
                    catalog={registeredFrameworks.data ?? []}
                  />
                ),
              },
              {
                label: "Control families",
                content: <ControlFamilies embedded />,
              },
              {
                label: "Test results",
                content: (
                  <QueryState queries={tests} label="control test results">
                    <div
                      role="region"
                      aria-label="Control test results"
                      tabIndex={0}
                      className="max-h-[440px] overflow-auto"
                    >
                      <ControlTestTable rows={tests.data ?? []} />
                    </div>
                  </QueryState>
                ),
              },
            ]}
          />
          <DashboardPanel
            title="Priority actions"
            storageKey="dashboard-operations-panel"
            tabs={[
              {
                label: "Findings",
                content: (
                  <FixNext embedded violations={data?.violations ?? []} />
                ),
              },
              {
                label: "Sources",
                content: (
                  <div className="p-4">
                    <div className="grid gap-3">
                      <IngestionStatusPanel status={ingestion.data} embedded />
                      <CollapsibleCard
                        storageKey="dashboard-eval-runs"
                        defaultOpen={ingestionNeedsAttention}
                        title="Evaluation cadence"
                        description={ingestionDescription}
                        actions={
                          ingestionNeedsAttention ? (
                            <Badge tone="attention">Action needed</Badge>
                          ) : undefined
                        }
                        contentClassName="p-0"
                      >
                        <EvalRunsStrip embedded limit={4} />
                      </CollapsibleCard>
                    </div>
                  </div>
                ),
              },
            ]}
          />
        </div>
      </QueryState>
    </div>
  );
}
