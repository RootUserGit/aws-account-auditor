export const SEVERITY_ORDER = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;
export const PILLAR_ORDER = ["security", "cost"] as const;

export const PILLAR_LABELS: Record<string, string> = {
  security: "Security",
  cost: "Cost optimization",
};
export const CHECK_STATUS_ORDER = ["failed", "passed", "unknown"] as const;

export const FINDINGS_PAGE_SIZE = 12;
export const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const DISPLAY_TZ_STORAGE_KEY = "audit-dashboard-display-timezone";

export const POLL_INITIAL_MS = 4000;
export const POLL_MAX_MS = 28000;
export const HISTORY_PAGE_SIZE = 10;

export const PIE_MOUNT_MS = 520;
export const BAR_MOUNT_MS = 480;
export const PIE_HOVER_OUTSET = 5;
