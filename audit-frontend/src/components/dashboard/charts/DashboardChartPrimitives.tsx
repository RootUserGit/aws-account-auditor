"use client";

import { useTheme } from "next-themes";
import {
  Rectangle,
  Sector,
  type BarShapeProps,
  type PieSectorShapeProps,
  type TooltipContentProps,
} from "recharts";
import type { CSSProperties } from "react";

import { PIE_HOVER_OUTSET } from "@/lib/constants/dashboard";

export const CHART_TOOLTIP_WRAPPER: CSSProperties = {
  outline: "none",
};

export function formatTooltipCount(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "number" || typeof value === "string")
    return String(value);
  if (Array.isArray(value)) return value.map(String).join(", ");
  return String(value);
}

export function DashboardPieSector(props: PieSectorShapeProps) {
  const { resolvedTheme } = useTheme();
  const isLight = resolvedTheme === "light";
  const { isActive, outerRadius, stroke, ...rest } = props;
  const base = Number(outerRadius) || 0;
  const strokeMuted = isLight ? "#f2f3f3" : "#0c1117";
  return (
    <Sector
      {...rest}
      outerRadius={base + (isActive ? PIE_HOVER_OUTSET : 0)}
      stroke={
        isActive
          ? "rgba(226, 232, 240, 0.42)"
          : ((stroke as string) ?? strokeMuted)
      }
      strokeWidth={isActive ? 2 : 1}
      style={{
        cursor: "pointer",
        transition:
          "filter 200ms cubic-bezier(0.22, 1, 0.36, 1), stroke-width 200ms cubic-bezier(0.22, 1, 0.36, 1)",
        filter: isActive ? "brightness(1.14) saturate(1.06)" : "brightness(1)",
      }}
    />
  );
}

export function DashboardStatusActiveBar(props: BarShapeProps) {
  const { x, y, width, height, fill, radius } = props;
  const pad = 3;
  const w = Math.max(0, width + pad * 2);
  return (
    <Rectangle
      x={x - pad}
      y={y}
      width={w}
      height={height}
      radius={radius ?? [6, 6, 0, 0]}
      fill={fill}
      stroke="rgba(248, 250, 252, 0.22)"
      strokeWidth={1}
      style={{
        transition: "filter 180ms ease-out, stroke-opacity 180ms ease-out",
        filter: "brightness(1.1)",
      }}
    />
  );
}

export function ChartCategoryCountTooltip(props: TooltipContentProps) {
  const { resolvedTheme } = useTheme();
  const isLight = resolvedTheme === "light";
  const { active, payload } = props;
  const show = Boolean(active && payload.length > 0);
  let label = "";
  let n = "";
  if (show) {
    const entry = payload[0];
    const row = entry?.payload as { name?: string } | undefined;
    const raw = row?.name ?? "";
    label =
      typeof raw === "string" && raw.length > 0
        ? raw.charAt(0).toUpperCase() + raw.slice(1).toLowerCase()
        : String(raw);
    n = formatTooltipCount(entry?.value);
  }
  return (
    <div
      className={
        "rounded-lg px-3 py-2 text-sm tabular-nums min-w-[7.5rem] min-h-[2.5rem] flex items-center " +
        (show
          ? isLight
            ? "text-gray-900 shadow ring-1 ring-gray-200"
            : "text-slate-200 shadow-xl ring-1 ring-white/5"
          : "opacity-0 pointer-events-none")
      }
      style={
        show
          ? {
              backgroundColor: isLight ? "#ffffff" : "#141a22",
              border: isLight ? "1px solid #d5dbdb" : "1px solid #414d5c",
              boxShadow: isLight
                ? "0 4px 12px rgba(0, 28, 36, 0.15)"
                : "0 8px 24px rgba(0, 0, 0, 0.35)",
            }
          : undefined
      }
      aria-hidden={!show}
    >
      {show ? `${label}: ${n}` : "\u00a0"}
    </div>
  );
}
