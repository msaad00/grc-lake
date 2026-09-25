"use client";

import Link from "next/link";
import { ClipboardCheck, FileCheck2, ShieldCheck } from "lucide-react";
import {
  useControlTests,
  useFrameworks,
  useIngestionStatus,
  usePosture,
  usePostureStream,
} from "@/lib/api/hooks";
import { DashboardPanel } from "@/components/dashboard/DashboardPanel";
import { DashboardStripsRow } from "@/components/dashboard/DashboardStripsRow";
import { AssessmentOverview } from "@/components/dashboard/AssessmentOverview";
import { ComplianceOverview } from "@/components/dashboard/ComplianceOverview";
import { ControlFamilies } from "@/components/dashboard/ControlFamilies";
import { ReadinessGrid } from "@/components/dashboard/ReadinessGrid";
import { FixNext } from "@/components/dashboard/FixNext";
import { EvidenceTrend } from "@/components/dashboard/EvidenceTrend";
import { ControlTestTable } from "@/components/dashboard/ControlTestTable";
import { TrustLifecycle } from "@/components/dashboard/TrustLifecycle";
import { IngestionStatusPanel } from "@/components/dashboard/IngestionStatusPanel";
import { EvalRunsStrip } from "@/components/dashboard/EvalRunsStrip";
import { DataPipelineStrip } from "@/components/dashboard/DataPipelineStrip";
import { KpiTile } from "@/components/ui/KpiTile";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { CollapsibleCard } from "@/components/ui/collapsible-card";
import { QueryState } from "@/components/QueryState";

// The API stamps UTC; the chip should show the viewer's calendar day.
export default function DashboardPage() {
  const posture = usePosture();
  const tests = useControlTests();
  const ingestion = useIngestionStatus();
  const registeredFrameworks = useFrameworks();
  usePostureStream();
  const data = posture.data;
  const p = data?.posture;
  const frameworks = data?.frameworks ?? [];
  const registeredCount =
    registeredFrameworks.data?.length ?? frameworks.length;
  const proofReady = Boolean(ingestion.data?.proof?.proof_pack_exists);
  const ingestionNeedsAttention =
    ingestion.data?.state !== "active" ||
    Boolean(ingestion.data?.recommended_actions?.length) ||
    Boolean(ingestion.data?.scale?.eval_overdue);
  const ingestionDescription = ingestionNeedsAttention
    ? (ingestion.data?.recommended_actions?.[0]?.reason ??
      "Connector health or control eval needs attention")
    : "Source sync health and control eval runs";

  return (
    <div className="page-shell grid gap-4">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div className="min-w-0">
          <h1 className="ui-page-title">Dashboard</h1>
        </div>
      </div>

      <QueryState queries={[posture, ingestion]} label="overview">
        <AssessmentOverview
          assessment={data}
          ingestion={ingestion.data}
          frameworkCount={registeredCount}
        />

        <div className="grid min-w-0 items-start gap-4 lg:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
          <DashboardPanel
            title="Compliance"
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
                  <div
                    role="region"
                    aria-label="Control test results"
                    tabIndex={0}
                    className="max-h-[440px] overflow-auto"
                  >
                    <ControlTestTable rows={tests.data ?? []} />
                  </div>
                ),
              },
            ]}
          />
          <DashboardPanel
            title="Operations"
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
                  <div className="p-3">
                    {" "}
                    <div className="grid gap-2">
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
              {
                label: "Exports",
                content: (
                  <div className="p-3">
                    {" "}
                    <div className="grid gap-2">
                      <div className="grid gap-2 sm:grid-cols-3 lg:grid-cols-1 2xl:grid-cols-3">
                        <KpiTile
                          label="Proof export"
                          value={proofReady ? "ready" : "pending"}
                          detail={
                            proofReady
                              ? `${ingestion.data?.proof?.evidence_count ?? 0} evidence rows in latest pack`
                              : "sync and evaluate to prepare export"
                          }
                          tone={proofReady ? "ready" : "attention"}
                          icon={<FileCheck2 className="h-3.5 w-3.5" />}
                        />
                        <KpiTile
                          label="Framework posture"
                          value={`${frameworks.length}/${registeredCount}`}
                          detail="Assessed frameworks"
                          tone="brand"
                          icon={<ClipboardCheck className="h-3.5 w-3.5" />}
                        />
                        <KpiTile
                          label="Assessment hash"
                          value={data?.assessment_hash?.slice(0, 8) ?? "—"}
                          detail="Current assessment"
                          tone={data?.assessment_hash ? "ready" : "default"}
                          icon={<ShieldCheck className="h-3.5 w-3.5" />}
                        />
                      </div>
                      <Card className="overflow-hidden p-3">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div>
                            <h2 className="text-base font-semibold text-ink">
                              Assessment exports
                            </h2>
                          </div>
                          <Link href="/audit-room">
                            <Badge tone="info">Open audit room</Badge>
                          </Link>
                        </div>
                        <div className="mt-3">
                          <ComplianceOverview frameworks={frameworks} />
                        </div>
                      </Card>
                      <TrustLifecycle
                        posture={p}
                        assessmentHash={data?.assessment_hash}
                      />
                    </div>
                  </div>
                ),
              },
            ]}
          />
        </div>

        <CollapsibleCard
          storageKey="dashboard-operational-detail"
          defaultOpen={false}
          title="Operational detail"
          contentClassName="grid gap-2 p-3"
        >
          <EvidenceTrend />
          <DashboardStripsRow />
          <DataPipelineStrip />
          <TrustLifecycle posture={p} assessmentHash={data?.assessment_hash} />
        </CollapsibleCard>
      </QueryState>
    </div>
  );
}
