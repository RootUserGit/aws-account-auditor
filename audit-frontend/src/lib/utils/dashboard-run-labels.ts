export function runStatusLabel(status: string): string {
  const s = status?.toLowerCase() ?? "";
  if (s === "succeeded") return "Succeeded";
  if (s === "failed") return "Failed";
  if (s === "queued") return "Queued";
  if (s === "running") return "Running";
  if (s === "cancelled") return "Cancelled";
  return status || "—";
}

export function runStatusClassName(status: string): string {
  const s = status?.toLowerCase() ?? "";
  if (s === "succeeded")
    return "text-emerald-700 dark:text-emerald-400 font-medium";
  if (s === "failed") return "text-red-600 dark:text-red-400 font-medium";
  if (s === "cancelled")
    return "text-amber-700 dark:text-amber-400/95 font-medium";
  if (s === "running") return "text-aws-orange font-medium";
  if (s === "queued")
    return "text-amber-800 dark:text-amber-200/90 font-medium";
  return "text-slate-600 dark:text-slate-300";
}
