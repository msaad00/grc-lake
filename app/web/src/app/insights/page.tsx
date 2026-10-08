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

function StatCard({
  label,
  value,
  tone,
  hint,
}: {
  label: string;
  value: string;
  tone?: "ok" | "warn" | "bad";
  hint?: string;
}) {
  const bg =
    tone === "bad"
      ? "bg-danger-bg border-danger/40"
      : tone === "warn"
        ? "bg-warning-bg border-warning/40"
        : "bg-surface border-line";
  const text =
    tone === "bad"
      ? "text-danger-fg"
      : tone === "warn"
        ? "text-warning-fg"
        : "text-ink";
  return (
    <div className={`rounded-2xl border p-5 ${bg}`}>
      <div className="text-[11px] font-semibold uppercase tracking-wider text-muted">
        {label}
      </div>
      <div className={`mt-1 text-3xl font-semibold ${text}`}>{value}</div>
      {hint && <p className="mt-1 text-xs leading-5 text-muted">{hint}</p>}
    </div>
  );
}

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
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <StatCard
              label="Open tasks"
              value={ins ? String(ins.open) : "—"}
              tone={ins && ins.open > 10 ? "warn" : "ok"}
            />
            <StatCard
              label="Overdue tasks"
              value={ins ? String(ins.overdue) : "—"}
              tone={ins && ins.overdue > 0 ? "bad" : "ok"}
            />
            <StatCard
              label="MTTR"
              value={fmt(ins?.mttr_hours, 1, " h")}
              hint={
                ins?.mttr_hours == null ? NO_RESOLVED_TASKS_HINT : undefined
              }
              tone={
                ins?.mttr_hours != null && ins.mttr_hours > 72 ? "warn" : "ok"
              }
            />
            <StatCard
              label="SLA attainment"
              value={fmt(ins?.sla_attainment_pct, 0, " %")}
              hint={
                ins?.sla_attainment_pct == null
                  ? NO_RESOLVED_TASKS_HINT
                  : undefined
              }
              tone={
                ins?.sla_attainment_pct != null && ins.sla_attainment_pct < 80
                  ? "bad"
                  : ins?.sla_attainment_pct != null &&
                      ins.sla_attainment_pct < 95
                    ? "warn"
                    : "ok"
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
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="var(--color-line)"
                    />
                    <XAxis
                      dataKey="date"
                      tick={{ fontSize: 11 }}
                      stroke="#94a3b8"
                    />
                    <YAxis
                      domain={[0, 100]}
                      tick={{ fontSize: 11 }}
                      stroke="#94a3b8"
                    />
                    <Tooltip
                      contentStyle={{
                        fontSize: 12,
                        borderRadius: 8,
                        border: "1px solid #e2e8f0",
                      }}
                    />
                    <Line
                      type="monotone"
                      dataKey="posture"
                      name="Posture score"
                      stroke="#4f7cff"
                      strokeWidth={2}
                      dot={false}
                    />
                    <Line
                      type="monotone"
                      dataKey="pass_rate"
                      name="Control pass rate"
                      stroke="#22c55e"
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
                          stopColor="#f87171"
                          stopOpacity={0.35}
                        />
                        <stop
                          offset="100%"
                          stopColor="#f87171"
                          stopOpacity={0.02}
                        />
                      </linearGradient>
                    </defs>
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="var(--color-line)"
                    />
                    <XAxis
                      dataKey="date"
                      tick={{ fontSize: 11 }}
                      stroke="#94a3b8"
                    />
                    <YAxis tick={{ fontSize: 11 }} stroke="#94a3b8" />
                    <Tooltip
                      contentStyle={{
                        fontSize: 12,
                        borderRadius: 8,
                        border: "1px solid #e2e8f0",
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="open"
                      name="Open findings"
                      stroke="#ef4444"
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
