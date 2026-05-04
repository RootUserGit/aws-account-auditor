import { SEVERITY_ORDER } from "@/lib/constants/dashboard";

export function severityRank(name: string): number {
  const i = SEVERITY_ORDER.indexOf(
    name.toLowerCase() as (typeof SEVERITY_ORDER)[number],
  );
  return i === -1 ? 99 : i;
}

export function colorForSeverity(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "#ef4444";
    case "high":
      return "#f97316";
    case "medium":
      return "#eab308";
    case "low":
      return "#38bdf8";
    case "info":
      return "#64748b";
    default:
      return "#94a3b8";
  }
}

export function colorForCheckStatus(status: string): string {
  switch (status.toLowerCase()) {
    case "passed":
      return "#34d399";
    case "failed":
      return "#f87171";
    case "unknown":
      return "#fbbf24";
    default:
      return "#64748b";
  }
}

export function chartTooltipFromTheme(light: boolean) {
  return {
    contentStyle: {
      backgroundColor: light ? "#ffffff" : "#141a22",
      border: light ? "1px solid #d5dbdb" : "1px solid #414d5c",
      borderRadius: "8px",
    },
    labelStyle: { color: light ? "#16191f" : "#e8eaef" },
    itemStyle: { color: light ? "#545b64" : "#cbd5e1" },
  };
}
