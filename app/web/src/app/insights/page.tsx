"use client";

import {
  useCaptureMetricMutation,
  useInsightsRemediation,
  useInsightsTimeseries,
} from "@/lib/api/hooks";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { EvidenceFreshnessTrendChart } from "@/components/insights/EvidenceFreshnessTrendChart";
import { FrameworkReadinessTrendChart } from "@/components/insights/FrameworkReadinessTrendChart";
import { SlaHeatmapPanel } from "@/components/insights/SlaHeatmapPanel";
import { QueryState } from "@/components/QueryState";
import { KpiTile, type KpiTone } from "@/components/ui/KpiTile";
import {
  AXIS_PROPS,
  CHART_SERIES,
  GRID_STROKE,
  TOOLTIP_CURSOR,
  TOOLTIP_LABEL_STYLE,
  TOOLTIP_STYLE,
} from "@/components/insights/chart-utils";
import { docsUrl } from "@/lib/format";
import { ROUTE_LABELS } from "@/lib/console-copy";

function fmtDate(iso: string): string {
  const d = new Date(iso);
  return `${d.getMonth() + 1}/${d.getDate()}`;
}

function fmt(v: number | null | undefined, digits = 1, suffix = ""): string {
  if (v == null) return "—";
  return `${v.toFixed(digits)}${suffix}`;
}

const NO_RESOLVED_TASKS_HINT = "Appears after the first task is resolved.";

type Tone = "ok" | "warn" | "bad";

const KPI_TONE: Record<Tone, KpiTone> = {
  ok: "default",
  warn: "attention",
  bad: "critical",
};

export default function InsightsPage() {
  const timeseries = useInsightsTimeseries(90);
  const remediation = useInsightsRemediation();
  const capture = useCaptureMetricMutation();

  const points = timeseries.data ?? [];
  const ins = remediation.data;

  const chartData = points.map((p) => ({
    date: fmtDate(p.captured_at),
    posture: +p.posture_score.toFixed(1),
    pass_rate: +(p.control_pass_rate * 100).toFixed(1),
    open: p.open_violations,
  }));

  return (
    <div className="page-shell grid gap-5">
      {/* header */}
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="text-[12px] font-semibold uppercase tracking-wider text-brand">
            Metrics &amp; trends
          </div>
          <h1 className="mt-1 text-3xl font-semibold text-ink">
            {ROUTE_LABELS["/insights"]}
          </h1>
          <p className="mt-2 max-w-[720px] text-sm text-muted">
            Posture score, framework readiness, evidence freshness, mean time to
            resolve (MTTR), and SLA attainment over time. Capture a data point
            now, or schedule a daily capture so trends fill in on their own.{" "}
            <a
              href={docsUrl("api/AGENT_API.md")}
              target="_blank"
              rel="noopener noreferrer"
              className="font-semibold text-brand hover:underline"
            >
              API reference
            </a>
          </p>
        </div>
        <Button
          size="sm"
          disabled={capture.isPending}
          onClick={() => capture.mutate()}
        >
          {capture.isPending ? "Capturing…" : "Capture now"}
        </Button>
      </div>

      <QueryState queries={[timeseries, remediation]} label="insights metrics">
        <>
          {/* remediation KPIs */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <KpiTile
              label="Open tasks"
              value={ins ? String(ins.open) : "—"}
              tone={KPI_TONE[ins && ins.open > 10 ? "warn" : "ok"]}
            />
            <KpiTile
              label="Overdue tasks"
              value={ins ? String(ins.overdue) : "—"}
              tone={KPI_TONE[ins && ins.overdue > 0 ? "bad" : "ok"]}
            />
            <KpiTile
              label="MTTR"
              value={fmt(ins?.mttr_hours, 1, " h")}
              detail={
                ins?.mttr_hours == null ? NO_RESOLVED_TASKS_HINT : undefined
              }
              tone={
                KPI_TONE[
                  ins?.mttr_hours != null && ins.mttr_hours > 72 ? "warn" : "ok"
                ]
              }
            />
            <KpiTile
              label="SLA attainment"
              value={fmt(ins?.sla_attainment_pct, 0, " %")}
              detail={
                ins?.sla_attainment_pct == null
                  ? NO_RESOLVED_TASKS_HINT
                  : undefined
              }
              tone={
                KPI_TONE[
                  ins?.sla_attainment_pct != null && ins.sla_attainment_pct < 80
                    ? "bad"
                    : ins?.sla_attainment_pct != null &&
                        ins.sla_attainment_pct < 95
                      ? "warn"
                      : "ok"
                ]
              }
            />
          </div>

          {/* posture score chart */}
          <Card className="overflow-hidden">
            <CardHeader>
              <CardTitle>Posture score over time</CardTitle>
              <CardDescription>
                Continuous compliance score (0–100) and control pass rate
                captured at each snapshot.
              </CardDescription>
            </CardHeader>
            <div
              className={`w-full px-2 pb-4 ${chartData.length === 0 ? "" : "h-[240px]"}`}
            >
              {chartData.length === 0 ? (
                <div className="flex h-full items-center justify-center py-6 text-center text-sm text-muted">
                  No data points yet — click &ldquo;Capture now&rdquo; to record
                  the first one.
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart
                    data={chartData}
                    margin={{ top: 4, right: 16, left: 0, bottom: 4 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke={GRID_STROKE} />
                    <XAxis dataKey="date" {...AXIS_PROPS} />
                    <YAxis domain={[0, 100]} {...AXIS_PROPS} />
                    <Tooltip
                      contentStyle={TOOLTIP_STYLE}
                      labelStyle={TOOLTIP_LABEL_STYLE}
                      cursor={TOOLTIP_CURSOR}
                    />
                    <Legend
                      wrapperStyle={{
                        fontSize: 11,
                        color: "var(--color-muted)",
                      }}
                    />
                    <Line
                      type="monotone"
                      dataKey="posture"
                      name="Posture score"
                      stroke={CHART_SERIES[0]}
                      strokeWidth={2}
                      dot={false}
                    />
                    <Line
                      type="monotone"
                      dataKey="pass_rate"
                      name="Control pass rate"
                      stroke={CHART_SERIES[1]}
                      strokeWidth={2}
                      dot={false}
                      strokeDasharray="4 2"
                    />
                  </LineChart>
                </ResponsiveContainer>
              )}
            </div>
          </Card>

          {/* open findings chart */}
          <Card className="overflow-hidden">
            <CardHeader>
              <CardTitle>Open findings over time</CardTitle>
              <CardDescription>
                Count of open findings at each captured snapshot.
              </CardDescription>
            </CardHeader>
            <div
              className={`w-full px-2 pb-4 ${chartData.length === 0 ? "" : "h-[200px]"}`}
            >
              {chartData.length === 0 ? (
                <div className="flex h-full items-center justify-center py-6 text-center text-sm text-muted">
                  No data points yet — capture one to start the trend.
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart
                    data={chartData}
                    margin={{ top: 4, right: 16, left: 0, bottom: 4 }}
                  >
                    <defs>
                      <linearGradient id="violGrad" x1="0" x2="0" y1="0" y2="1">
                        <stop
                          offset="0%"
                          stopColor="var(--color-danger)"
                          stopOpacity={0.35}
                        />
                        <stop
                          offset="100%"
                          stopColor="var(--color-danger)"
                          stopOpacity={0.02}
                        />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke={GRID_STROKE} />
                    <XAxis dataKey="date" {...AXIS_PROPS} />
                    <YAxis {...AXIS_PROPS} />
                    <Tooltip
                      contentStyle={TOOLTIP_STYLE}
                      labelStyle={TOOLTIP_LABEL_STYLE}
                      cursor={TOOLTIP_CURSOR}
                    />
                    <Area
                      type="monotone"
                      dataKey="open"
                      name="Open findings"
                      stroke="var(--color-danger)"
                      strokeWidth={2}
                      fill="url(#violGrad)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
          </Card>

          <FrameworkReadinessTrendChart />

          <EvidenceFreshnessTrendChart limit={90} />

          <SlaHeatmapPanel />
        </>
      </QueryState>
    </div>
  );
}
