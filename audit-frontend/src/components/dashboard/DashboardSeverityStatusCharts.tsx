"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  ChartCategoryCountTooltip,
  CHART_TOOLTIP_WRAPPER,
  DashboardPieSector,
  DashboardStatusActiveBar,
} from "@/components/dashboard/charts/DashboardChartPrimitives";
import { BAR_MOUNT_MS, PIE_MOUNT_MS } from "@/lib/constants/dashboard";
import { barChartPalette } from "@/lib/utils/dashboard-bar-chart-theme";
import { chartTooltipFromTheme } from "@/lib/utils/dashboard-chart";

type ChartRow = { name: string; value: number; fill: string };

function PieLegendLabel({
  value,
  isLight,
}: {
  readonly value: string;
  readonly isLight: boolean;
}) {
  return (
    <span
      className={
        isLight ? "text-gray-700 capitalize" : "text-slate-300 capitalize"
      }
    >
      {value}
    </span>
  );
}

export type DashboardSeverityStatusChartsProps = {
  readonly sevData: ChartRow[];
  readonly stData: ChartRow[];
  readonly chartTips: ReturnType<typeof chartTooltipFromTheme>;
  readonly pieRingStroke: string;
  readonly isLight: boolean;
};

export function DashboardSeverityStatusCharts({
  sevData,
  stData,
  chartTips,
  pieRingStroke,
  isLight,
}: DashboardSeverityStatusChartsProps) {
  const barPal = barChartPalette(isLight);
  const legendColor = isLight ? "#545b64" : "#cbd5e1";

  return (
    <div className="grid md:grid-cols-2 gap-8 min-h-[260px]">
      <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/40 p-4 min-w-0">
        <h3 className="text-xs font-medium dash-text-subtle uppercase tracking-wider mb-4">
          By severity
        </h3>
        {sevData.length === 0 ? (
          <p className="text-sm dash-text-muted py-12 text-center px-2">
            No summary yet — wait for run to finish.
          </p>
        ) : (
          <ResponsiveContainer width="100%" height={240}>
            <PieChart margin={{ top: 4, right: 4, left: 4, bottom: 4 }}>
              <Pie
                data={sevData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                outerRadius={72}
                innerRadius={34}
                paddingAngle={2}
                label={false}
                stroke={pieRingStroke}
                strokeWidth={1}
                rootTabIndex={-1}
                shape={DashboardPieSector}
                isAnimationActive="auto"
                animationBegin={0}
                animationDuration={PIE_MOUNT_MS}
                animationEasing="ease-out"
              >
                {sevData.map((entry) => (
                  <Cell key={entry.name} fill={entry.fill} />
                ))}
              </Pie>
              <Tooltip
                {...chartTips}
                isAnimationActive={false}
                wrapperStyle={CHART_TOOLTIP_WRAPPER}
                cursor={false}
                content={ChartCategoryCountTooltip}
              />
              <Legend
                verticalAlign="bottom"
                height={36}
                wrapperStyle={{
                  color: legendColor,
                  fontSize: 12,
                  paddingTop: 8,
                }}
                formatter={(value) => (
                  <PieLegendLabel value={String(value)} isLight={isLight} />
                )}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </div>
      <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/40 p-4 min-w-0">
        <h3 className="text-xs font-medium dash-text-subtle uppercase tracking-wider mb-4">
          By status
        </h3>
        {stData.length === 0 ? (
          <p className="text-sm dash-text-muted py-12 text-center px-2">
            No summary yet.
          </p>
        ) : (
          <ResponsiveContainer width="100%" height={240}>
            <BarChart
              data={stData}
              margin={{ top: 12, right: 8, left: 8, bottom: 28 }}
              barCategoryGap="20%"
            >
              <CartesianGrid
                strokeDasharray="3 3"
                stroke={barPal.grid}
                vertical={false}
              />
              <XAxis
                dataKey="name"
                stroke={barPal.tickStroke}
                tick={{ fill: barPal.tickFill, fontSize: 11 }}
                tickLine={false}
                axisLine={{ stroke: barPal.axisLine }}
                interval={0}
              />
              <YAxis
                width={44}
                stroke={barPal.tickStroke}
                tick={{ fill: barPal.tickFill, fontSize: 11 }}
                tickMargin={8}
                allowDecimals={false}
                axisLine={{ stroke: barPal.axisLine }}
              />
              <Tooltip
                {...chartTips}
                isAnimationActive={false}
                wrapperStyle={CHART_TOOLTIP_WRAPPER}
                cursor={{ fill: barPal.cursorFill }}
                content={ChartCategoryCountTooltip}
              />
              <Bar
                dataKey="value"
                radius={[6, 6, 0, 0]}
                maxBarSize={56}
                activeBar={DashboardStatusActiveBar}
                isAnimationActive="auto"
                animationBegin={0}
                animationDuration={BAR_MOUNT_MS}
                animationEasing="ease-out"
              >
                {stData.map((entry) => (
                  <Cell key={entry.name} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
