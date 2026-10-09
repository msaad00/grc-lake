"use client";

import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
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
import { useInsightsTimeseries } from "@/lib/api/hooks";
import {
  AXIS_PROPS,
  fmtChartDate,
  GRID_STROKE,
  TOOLTIP_CURSOR,
  TOOLTIP_LABEL_STYLE,
  TOOLTIP_STYLE,
} from "./chart-utils";

export function EvidenceFreshnessTrendChart({
  limit = 90,
}: {
  limit?: number;
}) {
  const timeseries = useInsightsTimeseries(limit);
  const points = timeseries.data ?? [];

  const chartData = points.map((p) => ({
    date: fmtChartDate(p.captured_at),
    fresh_pct: +(p.evidence_fresh_pct * 100).toFixed(1),
    stale_controls: p.stale_controls,
  }));

  return (
    <Card className="overflow-hidden">
      <CardHeader>
        <CardTitle>Evidence freshness trend</CardTitle>
        <CardDescription>
          Fresh evidence percentage and stale control count at each captured
          metrics snapshot.
        </CardDescription>
      </CardHeader>
      <div
        className={`w-full px-2 pb-4 ${chartData.length === 0 ? "" : "h-[240px]"}`}
      >
        {timeseries.isLoading ? (
          <div className="flex h-full items-center justify-center py-6 text-center text-sm text-muted">
            Loading freshness trend…
          </div>
        ) : chartData.length === 0 ? (
          <div className="flex h-full items-center justify-center py-6 text-center text-sm text-muted">
            No metrics snapshots yet — capture a point to plot evidence
            freshness over time.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              data={chartData}
              margin={{ top: 4, right: 16, left: 0, bottom: 4 }}
            >
              <defs>
                <linearGradient id="freshGrad" x1="0" x2="0" y1="0" y2="1">
                  <stop
                    offset="0%"
                    stopColor="var(--color-success)"
                    stopOpacity={0.35}
                  />
                  <stop
                    offset="100%"
                    stopColor="var(--color-success)"
                    stopOpacity={0.02}
                  />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={GRID_STROKE} />
              <XAxis dataKey="date" {...AXIS_PROPS} />
              <YAxis yAxisId="left" domain={[0, 100]} {...AXIS_PROPS} />
              <YAxis yAxisId="right" orientation="right" {...AXIS_PROPS} />
              <Tooltip
                contentStyle={TOOLTIP_STYLE}
                labelStyle={TOOLTIP_LABEL_STYLE}
                cursor={TOOLTIP_CURSOR}
              />
              <Area
                yAxisId="left"
                type="monotone"
                dataKey="fresh_pct"
                name="Fresh evidence %"
                stroke="var(--color-success)"
                strokeWidth={2}
                fill="url(#freshGrad)"
              />
              <Line
                yAxisId="right"
                type="monotone"
                dataKey="stale_controls"
                name="Stale controls"
                stroke="var(--color-warning)"
                strokeWidth={2}
                dot={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </Card>
  );
}
