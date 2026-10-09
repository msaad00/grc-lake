"use client";

import {
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
import { useInsightsFrameworkTrends } from "@/lib/api/hooks";
import {
  AXIS_PROPS,
  fmtChartDate,
  FRAMEWORK_LINE_COLORS,
  GRID_STROKE,
  TOOLTIP_CURSOR,
  TOOLTIP_LABEL_STYLE,
  TOOLTIP_STYLE,
} from "./chart-utils";

export function FrameworkReadinessTrendChart() {
  const trends = useInsightsFrameworkTrends(90);
  const frameworks = trends.data?.frameworks ?? [];
  const points = trends.data?.points ?? [];

  const chartData = points.map((p) => {
    const row: Record<string, string | number> = {
      date: fmtChartDate(p.at),
    };
    for (const fw of frameworks) {
      row[fw] = p.frameworks[fw] ?? null;
    }
    return row;
  });

  return (
    <Card className="overflow-hidden">
      <CardHeader>
        <CardTitle>Framework readiness over time</CardTitle>
        <CardDescription>
          Per-framework compliance scores from frozen snapshots and the live
          posture baseline.
        </CardDescription>
      </CardHeader>
      <div
        className={`w-full px-2 pb-4 ${chartData.length === 0 ? "" : "h-[260px]"}`}
      >
        {trends.isLoading ? (
          <div className="flex h-full items-center justify-center py-6 text-center text-sm text-muted">
            Loading framework trends…
          </div>
        ) : chartData.length === 0 ? (
          <div className="flex h-full items-center justify-center py-6 text-center text-sm text-muted">
            No snapshot history yet — freeze a snapshot from the audit room or
            capture metrics to start plotting framework readiness.
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
                wrapperStyle={{ fontSize: 11, color: "var(--color-muted)" }}
              />
              {frameworks.map((fw, index) => (
                <Line
                  key={fw}
                  type="monotone"
                  dataKey={fw}
                  name={fw}
                  stroke={
                    FRAMEWORK_LINE_COLORS[index % FRAMEWORK_LINE_COLORS.length]
                  }
                  strokeWidth={2}
                  dot={{ r: 2 }}
                  connectNulls
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </Card>
  );
}
