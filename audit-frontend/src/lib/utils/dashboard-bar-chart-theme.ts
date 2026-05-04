export function barChartPalette(isLight: boolean) {
  if (isLight) {
    return {
      grid: "#e9ebed",
      tickStroke: "#687078",
      tickFill: "#545b64",
      axisLine: "#d5dbdb",
      cursorFill: "rgba(84, 91, 100, 0.08)",
    };
  }
  return {
    grid: "#2d3548",
    tickStroke: "#64748b",
    tickFill: "#94a3b8",
    axisLine: "#334155",
    cursorFill: "rgba(148, 163, 184, 0.08)",
  };
}
