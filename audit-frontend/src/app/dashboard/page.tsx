"use client";

import { Suspense, useCallback, useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import Image from "next/image";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  Rectangle,
  ResponsiveContainer,
  Sector,
  Tooltip,
  type BarShapeProps,
  type PieSectorShapeProps,
  type TooltipContentProps,
  XAxis,
  YAxis,
} from "recharts";

import { SiteHeader } from "@/components/SiteHeader";
import { TimeZonePicker } from "@/components/TimeZonePicker";
import { isValidIanaTimeZone } from "@/data/timeZones";

const CHART_TOOLTIP = {
  contentStyle: {
    backgroundColor: "#141a22",
    border: "1px solid var(--border)",
    borderRadius: "8px",
  },
  labelStyle: { color: "#e8eaef" },
  itemStyle: { color: "#cbd5e1" },
};

/**
 * Recharts uses `left:0; top:0` + `transform: translate(...)` on the tooltip wrapper.
 * A CSS `transition` on `transform` looks smooth between slices, but after leaving the chart
 * the library often omits `transform` until the next hover — the browser then animates from
 * the default (top-left) into place. Keep wrapper motion off; sector/bar shapes handle hover polish.
 */
const CHART_TOOLTIP_WRAPPER: CSSProperties = {
  outline: "none",
};

const PIE_MOUNT_MS = 520;
const BAR_MOUNT_MS = 480;
const PIE_HOVER_OUTSET = 5;

function DashboardPieSector(props: PieSectorShapeProps) {
  const { isActive, outerRadius, stroke, ...rest } = props;
  const base = Number(outerRadius) || 0;
  return (
    <Sector
      {...rest}
      outerRadius={base + (isActive ? PIE_HOVER_OUTSET : 0)}
      stroke={isActive ? "rgba(226, 232, 240, 0.42)" : (stroke as string) ?? "#0c1117"}
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

function DashboardStatusActiveBar(props: BarShapeProps) {
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

function formatTooltipCount(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "number" || typeof value === "string") return String(value);
  if (Array.isArray(value)) return value.map(String).join(", ");
  return String(value);
}

/** Pie/bar summaries: show "High: 17" instead of a generic "Checks" label. */
function ChartCategoryCountTooltip(props: TooltipContentProps) {
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
        (show ? "text-slate-200 shadow-xl ring-1 ring-white/5" : "opacity-0 pointer-events-none")
      }
      style={
        show
          ? {
              backgroundColor: "#141a22",
              border: "1px solid var(--border)",
              boxShadow: "0 8px 24px rgba(0, 0, 0, 0.35)",
            }
          : undefined
      }
      aria-hidden={!show}
    >
      {show ? `${label}: ${n}` : "\u00a0"}
    </div>
  );
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const PILLAR_ORDER = ["security", "cost"] as const;
const PAGE_SIZE = 12;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function severityRank(name: string): number {
  const i = SEVERITY_ORDER.indexOf(name.toLowerCase() as (typeof SEVERITY_ORDER)[number]);
  return i === -1 ? 99 : i;
}

function colorForSeverity(severity: string): string {
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

function colorForCheckStatus(status: string): string {
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

type Account = {
  id: string;
  account_id: string;
  role_arn: string;
  status: string;
  last_verify_error_code?: string | null;
};

type ScanHistoryRow = {
  id: string;
  platform_account_id: string;
  aws_account_id: string;
  created_at?: string | null;
  status: string;
  rule_pack_version: string;
  error_code: string | null;
  started_at: string | null;
  finished_at: string | null;
  error_summary?: string | null;
  /** True until POST /runs returns — row id is `pending:<platformAccountUuid>` */
  optimistic?: boolean;
};

type FindingRow = {
  id: string;
  check_id: string;
  pillar: string;
  severity: string;
  status: string;
  remediation_hint?: string | null;
  evidence_json?: Record<string, unknown> | unknown[] | null;
};

type RunProgress = {
  phase?: string;
  rules_evaluated?: number;
  rules_total?: number;
  message?: string;
};

type RunSummary = {
  total?: number;
  by_severity?: Record<string, number>;
  by_pillar?: Record<string, number>;
  by_status?: Record<string, number>;
  groups?: Record<string, Record<string, number>>;
  failed_groups?: Record<string, Record<string, number>>;
  progress?: RunProgress;
};

const DISPLAY_TZ_STORAGE_KEY = "audit-dashboard-display-timezone";

function optimisticEnqueueRowId(platformAccountUuid: string): string {
  return `pending:${platformAccountUuid}`;
}

function browserDefaultTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

/** Resolve picker value to an IANA zone for Intl (API timestamps are ISO UTC). */
function resolveDisplayTimeZone(tzKey: string): string {
  if (tzKey === "local" || tzKey === "") return browserDefaultTimeZone();
  return tzKey;
}

/** Started / finished column — respects user-selected display timezone. */
function fmtAuditInstant(iso: string | null, tzKey: string): string {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    const iana = resolveDisplayTimeZone(tzKey);
    return d.toLocaleString(undefined, {
      timeZone: iana,
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
      hour12: true,
      timeZoneName: "short",
    });
  } catch {
    return iso;
  }
}

function readStoredDisplayTz(): string {
  if (typeof window === "undefined") return "local";
  try {
    const raw = localStorage.getItem(DISPLAY_TZ_STORAGE_KEY);
    if (!raw) return "local";
    if (raw === "local" || raw === "UTC") return raw;
    if (isValidIanaTimeZone(raw)) return raw;
  } catch {
    /* ignore */
  }
  return "local";
}

function normalizeScanHistoryRow(raw: unknown): ScanHistoryRow | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  const id = typeof o.id === "string" ? o.id : "";
  if (!id) return null;
  const pid = o.platform_account_id;
  const platform_account_id =
    typeof pid === "string" ? pid : typeof pid === "number" ? String(pid) : "";
  return {
    id,
    platform_account_id,
    aws_account_id: typeof o.aws_account_id === "string" ? o.aws_account_id : "",
    created_at: typeof o.created_at === "string" ? o.created_at : null,
    status: typeof o.status === "string" ? o.status : "",
    rule_pack_version: typeof o.rule_pack_version === "string" ? o.rule_pack_version : "v1",
    error_code: o.error_code === null || typeof o.error_code === "string" ? o.error_code : null,
    started_at: o.started_at === null || typeof o.started_at === "string" ? o.started_at : null,
    finished_at: o.finished_at === null || typeof o.finished_at === "string" ? o.finished_at : null,
    error_summary: o.error_summary === null || typeof o.error_summary === "string" ? o.error_summary : null,
  };
}

/** Finished scan duration: m:ss under 1h, h:mm under 24h, d:hh:mm from 1 day up */
function formatDurationMs(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const secTotal = Math.floor(ms / 1000);
  const days = Math.floor(secTotal / 86400);
  const hours = Math.floor((secTotal % 86400) / 3600);
  const minutes = Math.floor((secTotal % 3600) / 60);
  const seconds = secTotal % 60;
  if (days >= 1) {
    return `${days}:${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}`;
  }
  if (secTotal >= 3600) {
    return `${hours}:${String(minutes).padStart(2, "0")}`;
  }
  return `${minutes}:${String(seconds).padStart(2, "0")}`;
}

function runStatusLabel(status: string): string {
  const s = status?.toLowerCase() ?? "";
  if (s === "succeeded") return "Succeeded";
  if (s === "failed") return "Failed";
  if (s === "queued") return "Queued";
  if (s === "running") return "Running";
  if (s === "cancelled") return "Cancelled";
  return status || "—";
}

function runStatusClassName(status: string): string {
  const s = status?.toLowerCase() ?? "";
  if (s === "succeeded") return "text-emerald-400 font-medium";
  if (s === "failed") return "text-red-400 font-medium";
  if (s === "cancelled") return "text-amber-400/95 font-medium";
  if (s === "running") return "text-aws-orange font-medium";
  if (s === "queued") return "text-amber-200/90 font-medium";
  return "text-slate-300";
}

function normalizeRunDetail(raw: Record<string, unknown> | null): {
  status: string;
  summary_json: RunSummary | null;
  started_at: string | null;
  finished_at: string | null;
  error_summary: string | null;
  error_code: string | null;
} | null {
  if (!raw || typeof raw !== "object") return null;
  return {
    status: typeof raw.status === "string" ? raw.status : String(raw.status ?? ""),
    summary_json: (raw.summary_json as RunSummary | null) ?? null,
    started_at: typeof raw.started_at === "string" ? raw.started_at : null,
    finished_at: typeof raw.finished_at === "string" ? raw.finished_at : null,
    error_summary: raw.error_summary === null || typeof raw.error_summary === "string" ? raw.error_summary : null,
    error_code: raw.error_code === null || typeof raw.error_code === "string" ? raw.error_code : null,
  };
}

function parseIsoMs(iso: string | null): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : null;
}

function playbookFromEvidence(ev: FindingRow["evidence_json"]): string[] {
  if (!ev || typeof ev !== "object" || Array.isArray(ev)) return [];
  const pb = (ev as Record<string, unknown>).remediation_playbook;
  return Array.isArray(pb) ? pb.filter((x): x is string => typeof x === "string") : [];
}

function groupKey(pillar: string, severity: string): string {
  return `${pillar}|${severity}`;
}

type PrecheckEntry = {
  id?: string;
  label?: string;
  aws_error_code?: string;
  detail?: string;
  iam_actions?: string[];
  hint?: string;
  resource?: string;
};

function formatEnqueueError(data: unknown): string {
  if (!data || typeof data !== "object") return "Run failed";
  const detail = (data as { detail?: unknown }).detail;
  if (typeof detail === "string") return detail;
  if (detail && typeof detail === "object") {
    const d = detail as {
      message?: unknown;
      code?: unknown;
      blocking?: unknown;
    };
    if (Array.isArray(d.blocking) && d.blocking.length > 0) {
      const head: string[] = [];
      const msg = String(
        d.message ??
          "Permission precheck failed — AWS denied a required read operation for this audit.",
      );
      head.push(msg);
      if (d.code != null && String(d.code).length > 0) {
        head.push(`Reference code: ${String(d.code)}`);
      }
      const lines = [...head, ""];
      for (const b of d.blocking) {
        if (b && typeof b === "object") {
          const row = b as PrecheckEntry;
          const title = row.label ?? row.id ?? "Check";
          const code = row.aws_error_code ? ` — ${row.aws_error_code}` : "";
          lines.push(`• ${title}${code}`);
          if (row.resource) lines.push(`  Resource: ${row.resource}`);
          if (row.detail) lines.push(`  ${String(row.detail).replace(/\n/g, "\n  ")}`);
          if (row.iam_actions && row.iam_actions.length > 0) {
            lines.push(`  IAM actions to allow: ${row.iam_actions.join(", ")}`);
          }
          if (row.hint) lines.push(`  ${row.hint}`);
          lines.push("");
        }
      }
      return lines.join("\n").trimEnd();
    }
    if ("message" in detail) {
      return String((detail as { message: unknown }).message);
    }
  }
  return "Run failed";
}

const POLL_INITIAL_MS = 4000;
const POLL_MAX_MS = 28000;
const HISTORY_PAGE_SIZE = 10;

function DashboardContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const runParam = searchParams.get("run")?.trim() ?? "";
  const runId = UUID_RE.test(runParam) ? runParam : "";

  const [accounts, setAccounts] = useState<Account[]>([]);
  const [scanHistory, setScanHistory] = useState<ScanHistoryRow[]>([]);
  const [run, setRun] = useState<{
    status: string;
    summary_json: RunSummary | null;
    started_at: string | null;
    finished_at: string | null;
    error_summary: string | null;
    error_code: string | null;
  } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [refetchBusy, setRefetchBusy] = useState(false);
  const [failedOnly, setFailedOnly] = useState(true);
  const [legacySplit, setLegacySplit] = useState<{
    groups: Record<string, Record<string, number>>;
    failed_groups: Record<string, Record<string, number>>;
  } | null>(null);
  const [startingAccountId, setStartingAccountId] = useState<string | null>(null);
  const [precheckWarnings, setPrecheckWarnings] = useState<PrecheckEntry[] | null>(null);
  const [historyPage, setHistoryPage] = useState(0);
  const [historyTotal, setHistoryTotal] = useState(0);
  /** Wall clock for live duration labels (updated every 1s while scans run). */
  const [scanClockMs, setScanClockMs] = useState(() => Date.now());
  /** Persisted display timezone for Started / Finished (API stores UTC). */
  const [displayTz, setDisplayTz] = useState(() => readStoredDisplayTz());

  const pollBackoffRef = useRef(POLL_INITIAL_MS);
  /** Prevents duplicate POST before React re-renders disabled state. */
  const enqueueInflightRef = useRef(new Set<string>());

  const activeScanAccountIds = useMemo(() => {
    const ids = new Set<string>();
    for (const row of scanHistory) {
      const st = row.status?.toLowerCase() ?? "";
      if (st === "queued" || st === "running") ids.add(row.platform_account_id);
    }
    return ids;
  }, [scanHistory]);

  function accountScanBlocked(platformAccountId: string): boolean {
    return activeScanAccountIds.has(platformAccountId) || startingAccountId === platformAccountId;
  }

  /** Loaded pages per pillar|severity */
  const [pages, setPages] = useState<
    Record<string, { items: FindingRow[]; total: number; skip: number; loaded: boolean }>
  >({});

  const loadScanHistory = useCallback(async () => {
    try {
      const skip = historyPage * HISTORY_PAGE_SIZE;
      const res = await fetch(
        `/api/backend/runs?skip=${skip}&limit=${HISTORY_PAGE_SIZE}`,
        { cache: "no-store" },
      );
      if (!res.ok) return;
      const total = Number.parseInt(res.headers.get("X-Total-Count") ?? "0", 10);
      if (!Number.isNaN(total)) setHistoryTotal(total);
      const rows = await res.json();
      if (Array.isArray(rows)) setScanHistory(rows as ScanHistoryRow[]);
    } catch {
      /* ignore */
    }
  }, [historyPage]);

  useEffect(() => {
    queueMicrotask(() => {
      const maxPage = Math.max(0, Math.ceil(historyTotal / HISTORY_PAGE_SIZE) - 1);
      if (historyTotal === 0 && historyPage > 0) {
        setHistoryPage(0);
        return;
      }
      if (historyTotal > 0 && historyPage > maxPage) {
        setHistoryPage(maxPage);
      }
    });
  }, [historyTotal, historyPage]);

  function persistDisplayTz(next: string) {
    setDisplayTz(next);
    try {
      localStorage.setItem(DISPLAY_TZ_STORAGE_KEY, next);
    } catch {
      /* ignore */
    }
  }

  useEffect(() => {
    fetch("/api/backend/accounts")
      .then(async (r) => {
        const data = await r.json().catch(() => null);
        if (!r.ok) {
          setAccounts([]);
          if (r.status === 401) {
            setErr(
              "API returned 401 — set AUDIT_API_KEY in audit-frontend/.env.local to match the audit-api key (see README local development).",
            );
          } else {
            setErr("Failed to load accounts");
          }
          return;
        }
        if (Array.isArray(data)) {
          setAccounts(data as Account[]);
          setErr(null);
        } else {
          setAccounts([]);
          setErr("Unexpected accounts response");
        }
      })
      .catch(() => {
        setAccounts([]);
        setErr("Failed to load accounts");
      });
  }, []);

  useEffect(() => {
    queueMicrotask(() => void loadScanHistory());
  }, [loadScanHistory]);

  useEffect(() => {
    const activeRunningRow = scanHistory.some(
      (r) => (r.status?.toLowerCase() ?? "") === "running",
    );
    const activeRunningDetail =
      Boolean(runId) &&
      run &&
      (typeof run.status === "string" ? run.status.toLowerCase() : "") === "running";
    if (!activeRunningRow && !activeRunningDetail) return;
    const id = window.setInterval(() => setScanClockMs(Date.now()), 1000);
    return () => clearInterval(id);
  }, [scanHistory, runId, run, run?.status]);

  useEffect(() => {
    if (!runId) {
      queueMicrotask(() => {
        setRun(null);
        setPages({});
        setLegacySplit(null);
        setPrecheckWarnings(null);
      });
      return;
    }

    pollBackoffRef.current = POLL_INITIAL_MS;
    let cancelled = false;
    let timeoutId: number | null = null;

    const clearTimer = () => {
      if (timeoutId !== null) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }
    };

    const scheduleNextPoll = () => {
      if (cancelled) return;
      const wait = pollBackoffRef.current;
      pollBackoffRef.current = Math.min(POLL_MAX_MS, Math.floor(wait * 1.45));
      timeoutId = window.setTimeout(() => {
        void tick();
      }, wait);
    };

    const isRunFinished = (data: Record<string, unknown>): boolean => {
      const raw = data.status;
      const normalized = typeof raw === "string" ? raw.trim().toLowerCase() : "";
      if (normalized === "succeeded" || normalized === "failed" || normalized === "cancelled") return true;
      if (data.finished_at != null && data.finished_at !== "") return true;
      return false;
    };

    const tick = async () => {
      if (cancelled) return;
      let finished = false;
      try {
        const res = await fetch(`/api/backend/runs/${runId}`, { cache: "no-store" });
        const data = (await res.json().catch(() => null)) as Record<string, unknown> | null;
        if (cancelled || !res.ok || !data) {
          if (!cancelled && runId && !res.ok) setErr("Run not found or inaccessible.");
          if (!cancelled && !finished) scheduleNextPoll();
          return;
        }

        finished = isRunFinished(data);
        const parsed = normalizeRunDetail(data);
        if (parsed) setRun(parsed);
        setErr(null);

        // Keep scan history rows (queued/running/succeeded) in sync with the detail poll — not only on terminal state.
        void loadScanHistory();

        if (finished) {
          pollBackoffRef.current = POLL_INITIAL_MS;
        }
      } catch {
        /* retry later with backoff */
      }

      if (cancelled || finished) return;
      scheduleNextPoll();
    };

    void tick();

    return () => {
      cancelled = true;
      clearTimer();
    };
  }, [runId, loadScanHistory]);

  /** Legacy runs: derive groups once from a capped fetch (counts only — details stay behind accordions). */
  useEffect(() => {
    if (!runId || run?.status !== "succeeded" || run.summary_json?.groups) {
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(`/api/backend/runs/${runId}/findings?limit=400`, {
          cache: "no-store",
        });
        const rows = await res.json().catch(() => []);
        if (cancelled || !Array.isArray(rows)) return;
        const groups: Record<string, Record<string, number>> = {};
        const failed_groups: Record<string, Record<string, number>> = {};
        for (const raw of rows as FindingRow[]) {
          const p = raw.pillar || "unknown";
          const s = raw.severity || "unknown";
          groups[p] ??= {};
          groups[p][s] = (groups[p][s] ?? 0) + 1;
          if (raw.status === "failed") {
            failed_groups[p] ??= {};
            failed_groups[p][s] = (failed_groups[p][s] ?? 0) + 1;
          }
        }
        setLegacySplit({ groups, failed_groups });
      } catch {
        /* ignore */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [runId, run?.status, run?.summary_json?.groups]);

  useEffect(() => {
    queueMicrotask(() => {
      setPages({});
    });
  }, [runId, failedOnly]);

  async function cancelScan(targetRunId: string) {
    try {
      const res = await fetch(`/api/backend/runs/${encodeURIComponent(targetRunId)}/cancel`, {
        method: "POST",
      });
      if (!res.ok) {
        const data = (await res.json().catch(() => ({}))) as { detail?: unknown };
        const d = data.detail;
        const msg =
          typeof d === "string"
            ? d
            : d && typeof d === "object" && "message" in d
              ? String((d as { message: unknown }).message)
              : "Could not cancel scan";
        setErr(msg);
        return;
      }
      setErr(null);
      await loadScanHistory();
      if (runId === targetRunId) {
        try {
          const rr = await fetch(`/api/backend/runs/${encodeURIComponent(targetRunId)}`, {
            cache: "no-store",
          });
          const payload = (await rr.json().catch(() => null)) as Record<string, unknown> | null;
          const parsed = normalizeRunDetail(payload);
          if (rr.ok && parsed) setRun(parsed);
          else
            setRun((prev) =>
              prev
                ? {
                    ...prev,
                    status: "cancelled",
                    finished_at: new Date().toISOString(),
                    error_code: "Cancelled",
                    error_summary: prev.error_summary ?? "Cancelled",
                  }
                : prev,
            );
        } catch {
          setRun((prev) =>
            prev
              ? {
                  ...prev,
                  status: "cancelled",
                  finished_at: new Date().toISOString(),
                  error_code: "Cancelled",
                  error_summary: prev.error_summary ?? "Cancelled",
                }
              : prev,
          );
        }
      }
    } catch {
      setErr("Could not cancel scan");
    }
  }

  async function startRun(platformAccountUuid: string) {
    if (enqueueInflightRef.current.has(platformAccountUuid)) return;
    if (activeScanAccountIds.has(platformAccountUuid)) {
      setErr("This account already has a queued or running audit. Wait for it to finish.");
      return;
    }
    const pendId = optimisticEnqueueRowId(platformAccountUuid);
    const acc = accounts.find((a) => a.id === platformAccountUuid);
    const optimisticRow: ScanHistoryRow = {
      id: pendId,
      platform_account_id: platformAccountUuid,
      aws_account_id: acc?.account_id ?? "—",
      created_at: new Date().toISOString(),
      status: "queued",
      rule_pack_version: "v1",
      error_code: null,
      started_at: null,
      finished_at: null,
      error_summary: null,
      optimistic: true,
    };

    enqueueInflightRef.current.add(platformAccountUuid);
    setErr(null);
    setStartingAccountId(platformAccountUuid);
    setHistoryPage(0);
    setScanHistory((prev) => {
      const rest = prev.filter((r) => r.id !== pendId);
      return [optimisticRow, ...rest].slice(0, HISTORY_PAGE_SIZE);
    });

    function dropPending() {
      setScanHistory((prev) => prev.filter((r) => r.id !== pendId));
    }

    try {
      const res = await fetch(`/api/backend/accounts/${platformAccountUuid}/runs`, {
        method: "POST",
      });
      const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
      if (!res.ok) {
        dropPending();
        setPrecheckWarnings(null);
        setErr(formatEnqueueError(data));
        return;
      }
      const pw = data.precheck_warnings;
      setPrecheckWarnings(
        Array.isArray(pw) && pw.length > 0 ? (pw as PrecheckEntry[]) : null,
      );
      const id = typeof data.run_id === "string" ? data.run_id : "";
      if (!id) {
        dropPending();
        setErr("No run_id returned");
        return;
      }
      const immediateRow = normalizeScanHistoryRow(data.run);
      setScanHistory((prev) => {
        const rest = prev.filter((r) => r.id !== pendId);
        if (immediateRow) {
          const withoutDup = rest.filter((r) => r.id !== immediateRow.id);
          return [immediateRow, ...withoutDup].slice(0, HISTORY_PAGE_SIZE);
        }
        return rest;
      });
      router.replace(`/dashboard?run=${encodeURIComponent(id)}`);
      await loadScanHistory();
    } catch {
      dropPending();
      setErr("Could not start audit — network error.");
    } finally {
      enqueueInflightRef.current.delete(platformAccountUuid);
      setStartingAccountId(null);
    }
  }

  function openRun(id: string) {
    router.replace(`/dashboard?run=${encodeURIComponent(id)}`);
  }

  function clearRunView() {
    router.replace("/dashboard");
    setErr(null);
    setPrecheckWarnings(null);
  }

  async function manualRefetch() {
    if (!runId) return;
    setRefetchBusy(true);
    try {
      const res = await fetch(`/api/backend/runs/${runId}`, { cache: "no-store" });
      const data = (await res.json().catch(() => null)) as Record<string, unknown> | null;
      if (!res.ok || !data) {
        setErr("Could not refetch run");
        return;
      }
      const parsed = normalizeRunDetail(data);
      if (parsed) setRun(parsed);
      setErr(null);
      setPages({});
      void loadScanHistory();
    } finally {
      setRefetchBusy(false);
    }
  }

  async function fetchGroupPage(pillar: string, severity: string, skip: number) {
    const key = groupKey(pillar, severity);
    const params = new URLSearchParams({
      pillar,
      severity,
      skip: String(skip),
      limit: String(PAGE_SIZE),
    });
    if (failedOnly) params.set("status", "failed");
    const res = await fetch(`/api/backend/runs/${runId}/findings?${params}`, {
      cache: "no-store",
    });
    const total = Number.parseInt(res.headers.get("X-Total-Count") ?? "0", 10);
    const items = (await res.json().catch(() => [])) as FindingRow[];
    setPages((prev) => ({
      ...prev,
      [key]: { items: Array.isArray(items) ? items : [], total, skip, loaded: true },
    }));
  }

  function onGroupToggle(open: boolean, pillar: string, severity: string) {
    const key = groupKey(pillar, severity);
    if (!open || !runId) return;
    setPages((prev) => {
      if (prev[key]?.loaded) return prev;
      return { ...prev, [key]: { items: [], total: 0, skip: 0, loaded: false } };
    });
    void fetchGroupPage(pillar, severity, 0);
  }

  const terminal =
    run?.status === "succeeded" ||
    run?.status === "failed" ||
    run?.status === "cancelled";

  const terminalRunUnsuccessful =
    terminal && (run?.status === "failed" || run?.status === "cancelled");

  const summary = run?.summary_json;
  const runProgress = summary?.progress;
  const mergedGroups = summary?.groups ?? legacySplit?.groups;
  const mergedFailedGroups = summary?.failed_groups ?? legacySplit?.failed_groups;

  const sevData = useMemo(() => {
    const src = summary?.by_severity;
    if (!src) return [];
    return Object.entries(src)
      .map(([name, value]) => ({
        name,
        value,
        fill: colorForSeverity(name),
      }))
      .sort((a, b) => severityRank(a.name) - severityRank(b.name));
  }, [summary?.by_severity]);

  const stData = useMemo(() => {
    const src = summary?.by_status;
    if (!src) return [];
    const STATUS_ORDER = ["failed", "passed", "unknown"];
    function statusRank(name: string): number {
      const i = STATUS_ORDER.indexOf(name.toLowerCase());
      return i === -1 ? 99 : i;
    }
    return Object.entries(src)
      .map(([name, value]) => ({
        name,
        value,
        fill: colorForCheckStatus(name),
      }))
      .sort((a, b) => statusRank(a.name) - statusRank(b.name));
  }, [summary?.by_status]);

  const pillarLabels: Record<string, string> = {
    security: "Security",
    cost: "Cost optimization",
  };

  const structuredGroups = useMemo(() => {
    const out: { pillar: string; severity: string; count: number }[] = [];
    if (!mergedGroups && !mergedFailedGroups) return out;

    function countInGroup(pillar: string, severity: string): number {
      const src = failedOnly ? mergedFailedGroups : mergedGroups;
      return src?.[pillar]?.[severity] ?? 0;
    }

    const pillars = [
      ...PILLAR_ORDER,
      ...Object.keys({ ...mergedGroups, ...mergedFailedGroups }).filter(
        (p) => !PILLAR_ORDER.includes(p as (typeof PILLAR_ORDER)[number]),
      ),
    ];
    const seenP = new Set<string>();
    for (const pillar of pillars) {
      if (seenP.has(pillar)) continue;
      seenP.add(pillar);
      const severities = new Set<string>();
      if (mergedGroups?.[pillar]) Object.keys(mergedGroups[pillar]).forEach((s) => severities.add(s));
      if (mergedFailedGroups?.[pillar]) Object.keys(mergedFailedGroups[pillar]).forEach((s) => severities.add(s));
      const ordered = [
        ...SEVERITY_ORDER.filter((s) => severities.has(s)),
        ...[...severities].filter((s) => !SEVERITY_ORDER.includes(s as (typeof SEVERITY_ORDER)[number])),
      ];
      for (const severity of ordered) {
        const n = countInGroup(pillar, severity);
        if (n > 0) out.push({ pillar, severity, count: n });
      }
    }
    return out;
  }, [mergedGroups, mergedFailedGroups, failedOnly]);

  return (
    <div className="min-h-screen flex flex-col">
      <SiteHeader
        nav={[
          { href: "/", label: "Home" },
          { href: "/onboarding", label: "Onboard" },
          { href: "/dashboard", label: "Dashboard" },
        ]}
      />

      <main className="flex-1 max-w-6xl mx-auto w-full px-4 sm:px-6 py-8 space-y-10">
        <section className="flex flex-wrap gap-6 items-start justify-between">
          <div className="space-y-2 max-w-xl">
            <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-white">
              Operations dashboard
            </h1>
            <p className="text-sm text-slate-400 leading-relaxed">
              Audits are grouped by Well-Architected pillar and severity. Expand a group to load a{" "}
              <strong className="text-slate-300">paginated</strong> slice — findings stay collapsed until you open a row. While a run is
              active, status is refreshed in the background on a <strong className="text-slate-300">spaced polling</strong> schedule (not
              one-shot): the heavy work always runs in the worker.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <span className="relative h-14 w-28 opacity-90">
              <Image
                src="https://a0.awsstatic.com/libra-css/images/logos/aws_logo_smile_1200x630.png"
                alt=""
                fill
                className="object-contain object-right"
                sizes="112px"
              />
            </span>
          </div>
        </section>

        {err && (
          <p className="text-red-300 text-sm border border-red-900/60 bg-red-950/30 rounded-lg px-4 py-3 whitespace-pre-wrap">
            {err}
          </p>
        )}

        {precheckWarnings && precheckWarnings.length > 0 && (
          <div
            className="rounded-xl border border-amber-800/50 bg-amber-950/25 px-4 py-4 space-y-2"
            role="status"
          >
            <p className="text-sm font-semibold text-amber-100">
              Permission precheck: some optional collectors may be limited
            </p>
            <p className="text-xs text-slate-400 leading-relaxed">
              Required IAM actions passed; the scan was enqueued. Review gaps below and extend{" "}
              <code className="text-aws-orange/90 font-mono text-[11px]">policies/auditor-policy.json</code> on the customer role for fuller
              coverage.
            </p>
            <ul className="text-xs text-slate-300 list-disc pl-5 space-y-1">
              {precheckWarnings.map((w, i) => (
                <li key={`${w.id ?? i}-${i}`}>
                  <span className="font-medium text-slate-200">{w.label ?? w.id ?? "Check"}</span>
                  {w.aws_error_code ? (
                    <span className="text-slate-500"> — {w.aws_error_code}</span>
                  ) : null}
                  {w.detail ? <span className="block text-slate-500 mt-0.5">{w.detail}</span> : null}
                </li>
              ))}
            </ul>
            <button
              type="button"
              onClick={() => setPrecheckWarnings(null)}
              className="text-xs text-aws-orange hover:underline"
            >
              Dismiss
            </button>
          </div>
        )}

        <section className="space-y-3">
          <div className="flex flex-wrap justify-between items-center gap-3">
            <h2 className="text-sm font-medium text-slate-300 uppercase tracking-wider">Scan history</h2>
            <div className="flex flex-wrap items-center gap-3">
              <div
                className="flex items-center gap-2 text-xs text-slate-400"
                title="How Started and Finished times are shown (API stores UTC)"
              >
                <span className="whitespace-nowrap">Time zone</span>
                <TimeZonePicker value={displayTz} onChange={persistDisplayTz} />
              </div>
              <button
                type="button"
                onClick={() => void loadScanHistory()}
                className="text-xs text-aws-orange hover:underline"
              >
                Refresh list
              </button>
            </div>
          </div>
          <div className="overflow-x-auto rounded-xl border border-[var(--border)] bg-[var(--panel)]/60 shadow-xl shadow-black/20">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs uppercase tracking-wide text-slate-500">
                  <th className="p-3 font-medium">AWS account</th>
                  <th className="p-3 font-medium">Status</th>
                  <th className="p-3 font-medium" title="When the worker began executing the audit">
                    Started
                  </th>
                  <th className="p-3 font-medium">Finished</th>
                  <th className="p-3 font-medium" title="Worker execution time (finished − started)">
                    Duration
                  </th>
                  <th className="p-3 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {scanHistory.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-6 text-slate-500 text-center">
                      No runs on this page — start an audit from an account below or change page.
                    </td>
                  </tr>
                ) : (
                  scanHistory.map((row) => {
                    const active = row.id === runId;
                    const stLower = row.status?.toLowerCase() ?? "";
                    const isOptimistic = row.optimistic === true;
                    const isQueued = stLower === "queued";
                    const isRunning = stLower === "running";
                    const thisRowInFlight = isQueued || isRunning;
                    const startMs = parseIsoMs(row.started_at);
                    const endMs = parseIsoMs(row.finished_at);
                    let durationStr = "—";
                    if (isRunning && startMs != null) {
                      durationStr = formatDurationMs(scanClockMs - startMs);
                    } else if (!thisRowInFlight && startMs != null && endMs != null) {
                      durationStr = formatDurationMs(endMs - startMs);
                    }
                    const succeeded = stLower === "succeeded";
                    return (
                      <tr
                        key={row.id}
                        className={`border-t border-[var(--border)]/80 ${active ? "bg-aws-orange/5" : "hover:bg-[var(--panel-hover)]"}`}
                      >
                        <td className="p-3 font-mono text-xs text-slate-200">{row.aws_account_id}</td>
                        <td className="p-3 align-top">
                          <div className="flex flex-col gap-1.5">
                            <span className={runStatusClassName(row.status)}>{runStatusLabel(row.status)}</span>
                            {isOptimistic && isQueued ? (
                              <span className="text-[10px] text-slate-500">Confirming with server…</span>
                            ) : null}
                          </div>
                        </td>
                        <td className="p-3 text-slate-500 text-xs">{fmtAuditInstant(row.started_at, displayTz)}</td>
                        <td className="p-3 text-slate-500 text-xs">{fmtAuditInstant(row.finished_at, displayTz)}</td>
                        <td className="p-3 text-slate-400 text-xs font-mono tabular-nums">{durationStr}</td>
                        <td className="p-3">
                          {isOptimistic && isQueued ? (
                            <div className="flex items-center gap-2 text-xs text-slate-500">
                              <span
                                className="inline-block h-3.5 w-3.5 shrink-0 rounded-full border-2 border-slate-600 border-t-slate-300 animate-spin"
                                aria-hidden
                              />
                              <span>Hang tight — creating run…</span>
                            </div>
                          ) : isQueued ? (
                            <div className="flex flex-col gap-2 items-start">
                              <div className="flex flex-col gap-1 text-xs text-amber-200/90">
                                <div className="flex items-center gap-2">
                                  <span className="relative flex h-2 w-2 shrink-0 rounded-full bg-amber-400/80" />
                                  <span>In queue — execution has not started yet.</span>
                                </div>
                                <span className="text-[11px] text-slate-500 pl-4">
                                  Workers dequeue jobs from Redis. If this does not change, check worker health,
                                  logs, and that REDIS_URL matches the API.
                                </span>
                              </div>
                              <button
                                type="button"
                                onClick={() => void cancelScan(row.id)}
                                className="text-xs text-slate-400 hover:text-white underline-offset-2 hover:underline"
                              >
                                Cancel job
                              </button>
                            </div>
                          ) : thisRowInFlight ? (
                            <div className="flex flex-col gap-2 items-start">
                              <div className="flex items-center gap-2 text-xs text-aws-orange">
                                <span className="relative flex h-2 w-2 shrink-0">
                                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-aws-orange opacity-75" />
                                  <span className="relative inline-flex rounded-full h-2 w-2 bg-aws-orange" />
                                </span>
                                <span>
                                  Scan in progress ·{" "}
                                  {startMs != null ? formatDurationMs(scanClockMs - startMs) : "—"}
                                </span>
                              </div>
                              <button
                                type="button"
                                onClick={() => void cancelScan(row.id)}
                                className="text-xs text-slate-400 hover:text-white underline-offset-2 hover:underline"
                              >
                                Stop scan
                              </button>
                            </div>
                          ) : (
                            <div className="flex flex-wrap items-center gap-3">
                              <button
                                type="button"
                                onClick={() => openRun(row.id)}
                                className="text-aws-orange hover:underline text-xs font-medium"
                              >
                                View results
                              </button>
                              {succeeded ? (
                                <a
                                  href={`/api/backend/runs/${row.id}/report.html`}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="text-xs text-slate-400 hover:text-white hover:underline"
                                >
                                  HTML report
                                </a>
                              ) : null}
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
          <div className="flex flex-wrap justify-between items-center gap-2 text-xs text-slate-500">
            <span>
              {historyTotal === 0
                ? "0 runs"
                : `Showing ${historyPage * HISTORY_PAGE_SIZE + 1}–${Math.min(historyTotal, (historyPage + 1) * HISTORY_PAGE_SIZE)} of ${historyTotal}`}
            </span>
            <div className="flex gap-2">
              <button
                type="button"
                disabled={historyPage <= 0}
                onClick={() => {
                  setHistoryPage((p) => Math.max(0, p - 1));
                }}
                className="rounded-md border border-[var(--border)] px-2 py-1 hover:bg-[var(--panel-hover)] disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Previous
              </button>
              <button
                type="button"
                disabled={(historyPage + 1) * HISTORY_PAGE_SIZE >= historyTotal}
                onClick={() => {
                  setHistoryPage((p) => p + 1);
                }}
                className="rounded-md border border-[var(--border)] px-2 py-1 hover:bg-[var(--panel-hover)] disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-sm font-medium text-slate-300 uppercase tracking-wider">Connected accounts</h2>
          <div className="grid gap-4 md:grid-cols-2">
            {accounts.map((a) => {
              const busy = accountScanBlocked(a.id);
              const startingHere = startingAccountId === a.id;
              const accSt = (a.status ?? "").toLowerCase();
              return (
                <div
                  key={a.id}
                  className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/70 p-5 flex flex-col gap-3 shadow-lg shadow-black/15"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="font-mono text-sm text-white">{a.account_id}</div>
                    <span
                      className={`text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-full border ${
                        accSt === "verified"
                          ? "bg-emerald-950/45 text-emerald-400 border-emerald-600/40 font-semibold"
                          : accSt === "error"
                            ? "bg-red-950/30 text-red-300/90 border-red-800/40"
                            : "bg-white/5 text-slate-400 border-[var(--border)]"
                      }`}
                    >
                      {a.status}
                    </span>
                  </div>
                  <div className="text-xs truncate text-slate-500">{a.role_arn}</div>
                  {a.status === "error" && a.last_verify_error_code && (
                    <div className="text-xs text-amber-300 font-mono bg-amber-950/30 border border-amber-900/40 rounded-md px-2 py-1">
                      STS: {a.last_verify_error_code}
                    </div>
                  )}
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void startRun(a.id)}
                    className="mt-auto rounded-lg bg-aws-orange hover:bg-[var(--accent-muted)] disabled:opacity-55 disabled:cursor-not-allowed disabled:hover:bg-aws-orange text-aws-ink font-semibold text-sm py-2.5 transition-colors flex items-center justify-center gap-2 min-h-[42px]"
                  >
                    {startingHere ? (
                      <>
                        <span
                          className="inline-block h-4 w-4 shrink-0 rounded-full border-2 border-aws-ink/30 border-t-aws-ink animate-spin"
                          aria-hidden
                        />
                        Starting audit…
                      </>
                    ) : busy ? (
                      "Audit queued or running…"
                    ) : (
                      "Start audit run"
                    )}
                  </button>
                </div>
              );
            })}
          </div>
        </section>

        {runId && (
          <section className="space-y-6">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <h2 className="text-lg font-semibold text-white">Active run</h2>
                <p className="text-xs font-mono text-slate-500 mt-1 break-all">{runId}</p>
                <p className="text-sm text-slate-400 mt-2">
                  Status:{" "}
                  <span className={runStatusClassName(run?.status ?? "")}>
                    {runStatusLabel(run?.status ?? "…")}
                  </span>
                  {terminal ? (
                    <span className="text-slate-600 ml-2">· polling paused</span>
                  ) : (
                    <span className="text-aws-orange ml-2">· live updates</span>
                  )}
                </p>
                {!terminal && run?.status?.toLowerCase() === "queued" ? (
                  <p className="text-xs text-amber-200/85 mt-2 leading-relaxed max-w-xl">
                    This run is <strong className="font-medium text-amber-100/90">queued</strong>: it is in the
                    job queue until an audit worker begins processing. If it stays here, verify worker processes
                    are running and inspect their logs (connectivity, Redis, or errors before status updates).
                  </p>
                ) : null}
                {!terminal && run?.status?.toLowerCase() === "running" && run?.started_at ? (
                  <p className="text-xs text-slate-500 mt-2 font-mono tabular-nums">
                    Elapsed{" "}
                    <span className="text-aws-orange">
                      {formatDurationMs(scanClockMs - (parseIsoMs(run.started_at) ?? 0))}
                    </span>
                  </p>
                ) : null}
              </div>
              <div className="flex flex-wrap gap-2">
                {run?.status === "succeeded" ? (
                  <a
                    href={`/api/backend/runs/${runId}/report.html`}
                    className="text-sm rounded-lg border border-[var(--border)] px-3 py-2 text-aws-orange hover:bg-white/5"
                    target="_blank"
                    rel="noreferrer"
                  >
                    HTML report
                  </a>
                ) : null}
                <button
                  type="button"
                  onClick={() => void manualRefetch()}
                  disabled={refetchBusy}
                  className="text-sm rounded-lg border border-[var(--border)] px-3 py-2 hover:bg-[var(--panel-hover)] disabled:opacity-50"
                >
                  {refetchBusy ? "Refreshing…" : "Refresh"}
                </button>
                {!terminal ? (
                  <button
                    type="button"
                    onClick={() => void cancelScan(runId)}
                    className="text-sm rounded-lg border border-red-900/50 px-3 py-2 text-red-300 hover:bg-red-950/40"
                  >
                    Cancel scan
                  </button>
                ) : null}
                <button
                  type="button"
                  title="Hide this panel only — does not stop an in-flight audit (use Cancel scan)."
                  onClick={clearRunView}
                  className="text-sm rounded-lg border border-[var(--border)] px-3 py-2 hover:bg-[var(--panel-hover)]"
                >
                  Close panel
                </button>
              </div>
            </div>

            {!terminal && run?.status?.toLowerCase() === "queued" ? (
              <div
                className="flex flex-wrap items-start gap-4 rounded-xl border border-amber-700/40 bg-gradient-to-r from-amber-950/40 to-transparent px-4 py-4"
                role="status"
                aria-live="polite"
              >
                <span
                  className="inline-block h-10 w-10 shrink-0 rounded-full border-2 border-amber-500/50 mt-0.5"
                  aria-hidden
                />
                <div className="min-w-0 flex-1 space-y-1">
                  <p className="text-sm font-semibold text-amber-100/95 tracking-tight">Run queued</p>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    The audit has not started executing yet. Work runs in worker processes, not in your browser. This page polls status on an
                    interval from ~{POLL_INITIAL_MS / 1000}s up to ~{POLL_MAX_MS / 1000}s. Avoid starting another scan for the same account
                    until this run leaves the queue or finishes.
                  </p>
                  {runProgress?.phase ? (
                    <details className="mt-2 rounded-md border border-amber-800/35 bg-black/20">
                      <summary className="cursor-pointer text-xs text-amber-200/90 px-2 py-2 select-none">
                        Scan progress
                      </summary>
                      <div className="px-2 pb-2 pt-0 text-xs text-slate-400 space-y-1">
                        <p className="font-mono capitalize">{runProgress.phase.replace(/_/g, " ")}</p>
                        {runProgress.message ? <p className="text-slate-500">{runProgress.message}</p> : null}
                      </div>
                    </details>
                  ) : null}
                </div>
              </div>
            ) : null}
            {!terminal && run?.status?.toLowerCase() === "running" ? (
              <div
                className="flex flex-wrap items-start gap-4 rounded-xl border border-aws-orange/35 bg-gradient-to-r from-aws-orange/15 to-transparent px-4 py-4"
                role="status"
                aria-live="polite"
              >
                <span
                  className="inline-block h-10 w-10 shrink-0 rounded-full border-2 border-aws-orange border-t-transparent animate-spin mt-0.5"
                  aria-hidden
                />
                <div className="min-w-0 flex-1 space-y-1">
                  <p className="text-sm font-semibold text-white tracking-tight">Audit running</p>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Data collection and rule evaluation run in the audit worker — not in your browser. This page polls run status on an
                    interval that starts around {POLL_INITIAL_MS / 1000}s and gradually increases (cap ~{POLL_MAX_MS / 1000}s). You can leave
                    this tab open; avoid starting another scan for the same account until this one finishes.
                  </p>
                  {runProgress &&
                  (runProgress.rules_total != null ||
                    runProgress.phase != null ||
                    runProgress.message != null) ? (
                    <details className="mt-2 rounded-md border border-aws-orange/25 bg-black/25">
                      <summary className="cursor-pointer text-xs text-aws-orange px-2 py-2 select-none">
                        {runProgress.rules_total != null && runProgress.rules_total > 0 ? (
                          <>
                            Rule evaluation:{" "}
                            {Math.min(
                              100,
                              Math.round(
                                ((runProgress.rules_evaluated ?? 0) / runProgress.rules_total) * 100,
                              ),
                            )}
                            %
                            <span className="text-slate-500 font-normal ml-1">
                              ({runProgress.rules_evaluated ?? 0}/{runProgress.rules_total} checks)
                            </span>
                          </>
                        ) : (
                          <>Scan progress</>
                        )}
                      </summary>
                      <div className="px-2 pb-2 pt-0 text-xs text-slate-400 space-y-2">
                        {runProgress.phase ? (
                          <p className="font-mono capitalize">{runProgress.phase.replace(/_/g, " ")}</p>
                        ) : null}
                        {runProgress.message ? <p className="text-slate-500">{runProgress.message}</p> : null}
                        {runProgress.rules_total != null && runProgress.rules_total > 0 ? (
                          <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                            <div
                              className="h-full bg-aws-orange transition-[width] duration-300 ease-out"
                              style={{
                                width: `${Math.min(
                                  100,
                                  Math.round(
                                    ((runProgress.rules_evaluated ?? 0) / runProgress.rules_total) * 100,
                                  ),
                                )}%`,
                              }}
                            />
                          </div>
                        ) : null}
                      </div>
                    </details>
                  ) : null}
                </div>
              </div>
            ) : null}

            {terminalRunUnsuccessful ? (
              <div
                className={`flex flex-wrap items-start gap-4 rounded-xl border px-4 py-4 ${
                  run?.status === "failed"
                    ? "border-red-900/45 bg-red-950/20"
                    : "border-amber-800/40 bg-amber-950/15"
                }`}
                role="alert"
              >
                <span
                  className={`inline-block h-10 w-10 shrink-0 rounded-full border-2 mt-0.5 ${
                    run?.status === "failed"
                      ? "border-red-500/60 bg-red-500/10"
                      : "border-amber-500/50 bg-amber-500/10"
                  }`}
                  aria-hidden
                />
                <div className="min-w-0 flex-1 space-y-2">
                  <p
                    className={`text-sm font-semibold tracking-tight ${
                      run?.status === "failed" ? "text-red-200" : "text-amber-100"
                    }`}
                  >
                    {run?.status === "failed" ? "Scan failed" : "Scan cancelled"}
                  </p>
                  {run?.error_code ? (
                    <p className="text-xs font-mono text-slate-400">
                      <span className="text-slate-500">Error code: </span>
                      {run.error_code}
                    </p>
                  ) : null}
                  {run?.error_summary ? (
                    <pre className="text-xs text-slate-300 whitespace-pre-wrap break-words leading-relaxed rounded-md border border-white/10 bg-black/20 px-3 py-2.5">
                      {run.error_summary}
                    </pre>
                  ) : (
                    <p className="text-xs text-slate-500 leading-relaxed">
                      No detailed failure message was stored for this run. Use{" "}
                      <span className="text-slate-400">Refresh</span> after the worker finishes writing status, or
                      check worker logs if this persists.
                    </p>
                  )}
                  {run?.summary_json &&
                  typeof run.summary_json === "object" &&
                  run.summary_json !== null &&
                  Object.keys(run.summary_json).length > 0 ? (
                    <details className="rounded-md border border-white/10 bg-black/15 mt-1">
                      <summary className="cursor-pointer text-xs text-slate-500 hover:text-slate-400 px-3 py-2 select-none">
                        Technical details (raw summary JSON)
                      </summary>
                      <pre className="text-[11px] text-slate-400 whitespace-pre-wrap break-words px-3 pb-3 pt-0 font-mono leading-relaxed max-h-72 overflow-auto border-t border-white/5">
                        {JSON.stringify(run.summary_json, null, 2)}
                      </pre>
                    </details>
                  ) : null}
                </div>
              </div>
            ) : null}

            {terminal && run?.status === "succeeded" && summary != null && (summary.total ?? 0) === 0 ? (
              <div
                className="flex flex-wrap items-start gap-3 rounded-xl border border-amber-800/45 bg-amber-950/25 px-4 py-3"
                role="status"
              >
                <div className="min-w-0 flex-1 space-y-1">
                  <p className="text-sm font-medium text-amber-100/95">No checks were evaluated</p>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    This usually means the worker could not find any rule YAML under{" "}
                    <span className="font-mono text-slate-300">RULE_PACK_PATH</span>. Fix the worker environment,
                    rebuild the worker image so <span className="font-mono text-slate-300">rule_packs/v1</span> is
                    present, and run a new scan — charts and the HTML report stay empty when the rule pack resolves to
                    zero files.
                  </p>
                </div>
              </div>
            ) : null}

            {!terminalRunUnsuccessful ? (
              <>
            <div className="flex flex-wrap items-center gap-3 rounded-xl border border-[var(--border)] bg-[var(--panel)]/50 px-4 py-3">
              <span className="text-xs text-slate-500 uppercase tracking-wide">Findings filter</span>
              <button
                type="button"
                role="switch"
                aria-checked={!failedOnly}
                onClick={() => setFailedOnly((v) => !v)}
                className={`relative inline-flex h-7 w-12 shrink-0 rounded-full transition-colors ${failedOnly ? "bg-slate-700" : "bg-emerald-700"}`}
              >
                <span
                  className={`absolute top-0.5 left-0.5 h-6 w-6 rounded-full bg-white shadow transition-transform ${failedOnly ? "translate-x-0" : "translate-x-5"}`}
                />
              </button>
              <span className="text-sm text-slate-300">
                {failedOnly ? "Failed checks only (default)" : "All statuses (passed & unknown included)"}
              </span>
            </div>

            {summary && (
              <div className="space-y-2">
                <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/60 p-4">
                    <div className="text-[10px] uppercase tracking-widest text-slate-500">Checks evaluated</div>
                    <div className="text-2xl font-semibold text-white mt-1">{summary.total ?? "—"}</div>
                  </div>
                  <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/60 p-4">
                    <div className="text-[10px] uppercase tracking-widest text-slate-500">Failed</div>
                    <div className="text-2xl font-semibold text-red-400 mt-1">
                      {summary.by_status?.failed ?? "—"}
                    </div>
                  </div>
                  <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/60 p-4">
                    <div className="text-[10px] uppercase tracking-widest text-slate-500">Passed</div>
                    <div className="text-2xl font-semibold text-emerald-400 mt-1">
                      {summary.by_status?.passed ?? "—"}
                    </div>
                  </div>
                  <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/60 p-4">
                    <div className="text-[10px] uppercase tracking-widest text-slate-500">Unknown</div>
                    <div className="text-2xl font-semibold text-amber-200/95 mt-1 tabular-nums">
                      {summary.by_status?.unknown ?? "—"}
                    </div>
                  </div>
                </div>
                <p className="text-xs text-slate-500 leading-relaxed max-w-3xl">
                  <span className="text-slate-400">Unknown</span> means the rule could not decide pass/fail — usually
                  missing read permissions, empty inventory for that service in the sampled Regions, or a worker that is
                  behind the rule pack (shows as{" "}
                  <code className="text-slate-400 font-mono text-[11px]">unknown_evaluator:…</code> in evidence). Rebuild
                  and restart <span className="font-mono text-slate-400">audit-worker</span> after pulling new rules.
                </p>
              </div>
            )}

            <div className="grid md:grid-cols-2 gap-8 min-h-[260px]">
              <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/40 p-4 min-w-0">
                <h3 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-4">By severity</h3>
                {sevData.length === 0 ? (
                  <p className="text-sm text-slate-600 py-12 text-center px-2">
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
                        stroke="#0c1117"
                        strokeWidth={1}
                        rootTabIndex={-1}
                        shape={DashboardPieSector}
                        isAnimationActive="auto"
                        animationBegin={0}
                        animationDuration={PIE_MOUNT_MS}
                        animationEasing="ease-out"
                      >
                        {sevData.map((entry, i) => (
                          <Cell key={`${entry.name}-${i}`} fill={entry.fill} />
                        ))}
                      </Pie>
                      <Tooltip
                        {...CHART_TOOLTIP}
                        isAnimationActive={false}
                        wrapperStyle={CHART_TOOLTIP_WRAPPER}
                        cursor={false}
                        content={ChartCategoryCountTooltip}
                      />
                      <Legend
                        verticalAlign="bottom"
                        height={36}
                        wrapperStyle={{ color: "#cbd5e1", fontSize: 12, paddingTop: 8 }}
                        formatter={(value) => <span className="text-slate-300 capitalize">{value}</span>}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                )}
              </div>
              <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/40 p-4 min-w-0">
                <h3 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-4">By status</h3>
                {stData.length === 0 ? (
                  <p className="text-sm text-slate-600 py-12 text-center px-2">No summary yet.</p>
                ) : (
                  <ResponsiveContainer width="100%" height={240}>
                    <BarChart
                      data={stData}
                      margin={{ top: 12, right: 8, left: 8, bottom: 28 }}
                      barCategoryGap="20%"
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="#2d3548" vertical={false} />
                      <XAxis
                        dataKey="name"
                        stroke="#64748b"
                        tick={{ fill: "#94a3b8", fontSize: 11 }}
                        tickLine={false}
                        axisLine={{ stroke: "#334155" }}
                        interval={0}
                      />
                      <YAxis
                        width={44}
                        stroke="#64748b"
                        tick={{ fill: "#94a3b8", fontSize: 11 }}
                        tickMargin={8}
                        allowDecimals={false}
                        axisLine={{ stroke: "#334155" }}
                      />
                      <Tooltip
                        {...CHART_TOOLTIP}
                        isAnimationActive={false}
                        wrapperStyle={CHART_TOOLTIP_WRAPPER}
                        cursor={{ fill: "rgba(148, 163, 184, 0.08)" }}
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
                        {stData.map((entry, i) => (
                          <Cell key={`${entry.name}-${i}`} fill={entry.fill} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>

            <div className="space-y-4">
              <div className="flex flex-wrap justify-between items-center gap-2">
                <h3 className="text-sm font-medium text-slate-300 uppercase tracking-wider">Grouped findings</h3>
                {!mergedGroups && terminal && run?.status === "succeeded" && (
                  <span className="text-[10px] text-slate-500">
                    Re-run audits to store group metadata on the server; showing derived groups from a capped sample.
                  </span>
                )}
              </div>

              {structuredGroups.length === 0 && terminal && (
                <p className="text-sm text-slate-500 border border-dashed border-[var(--border)] rounded-xl p-6 text-center">
                  No grouped counts available yet. Re-run audits to store group metadata on the server, or wait for
                  summary data.
                </p>
              )}

              <div className="space-y-2">
                {PILLAR_ORDER.filter((p) => structuredGroups.some((g) => g.pillar === p)).map((pillar) => (
                  <details
                    key={pillar}
                    className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/50 overflow-hidden group/pillar"
                  >
                    <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-white hover:bg-[var(--panel-hover)] flex items-center justify-between gap-2 list-none [&::-webkit-details-marker]:hidden">
                      <span className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-aws-orange shrink-0" />
                        {pillarLabels[pillar] ?? pillar}
                      </span>
                      <span className="text-xs text-slate-500">
                        {structuredGroups.filter((g) => g.pillar === pillar).reduce((a, g) => a + g.count, 0)} checks
                      </span>
                    </summary>
                    <div className="border-t border-[var(--border)] px-2 pb-3 space-y-1">
                      {structuredGroups
                        .filter((g) => g.pillar === pillar)
                        .map(({ severity, count }) => {
                          const key = groupKey(pillar, severity);
                          const pageState = pages[key];
                          const pagesCount = pageState ? Math.ceil(pageState.total / PAGE_SIZE) : 1;
                          return (
                            <details
                              key={key}
                              className="rounded-lg border border-[var(--border)]/60 bg-[#0c1117]/40 overflow-hidden"
                              onToggle={(e) => {
                                const el = e.currentTarget;
                                onGroupToggle(el.open, pillar, severity);
                              }}
                            >
                              <summary className="cursor-pointer px-3 py-2.5 flex flex-wrap items-center justify-between gap-2 hover:bg-white/[0.03] list-none [&::-webkit-details-marker]:hidden">
                                <span className="flex items-center gap-2">
                                  <span
                                    className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border font-medium"
                                    style={{
                                      color: colorForSeverity(severity),
                                      borderColor: `${colorForSeverity(severity)}55`,
                                      background: `${colorForSeverity(severity)}14`,
                                    }}
                                  >
                                    {severity}
                                  </span>
                                  <span className="text-sm text-slate-300">
                                    {count} {failedOnly ? "failed" : "total"}
                                  </span>
                                </span>
                                <span className="text-[10px] text-slate-600">Click to load · paginated</span>
                              </summary>
                              <div className="border-t border-[var(--border)]/60 px-2 py-3 space-y-2">
                                {!pageState?.loaded && (
                                  <p className="text-xs text-slate-500 px-2">Loading…</p>
                                )}
                                {pageState?.loaded && pageState.items.length === 0 && (
                                  <p className="text-xs text-slate-500 px-2">No rows in this slice.</p>
                                )}
                                {pageState?.loaded &&
                                  pageState.items.map((f) => {
                                    const pb = playbookFromEvidence(f.evidence_json);
                                    return (
                                      <details
                                        key={f.id}
                                        className="rounded-lg bg-[var(--panel)]/80 border border-[var(--border)]/50 overflow-hidden"
                                      >
                                        <summary className="cursor-pointer px-3 py-2 flex flex-wrap items-center gap-2 text-left hover:bg-[var(--panel-hover)] list-none [&::-webkit-details-marker]:hidden">
                                          <span className="font-mono text-xs text-aws-orange shrink-0">{f.check_id}</span>
                                          <span
                                            className="text-[10px] px-1.5 py-0.5 rounded border capitalize"
                                            style={{
                                              color: colorForCheckStatus(f.status),
                                              borderColor: `${colorForCheckStatus(f.status)}44`,
                                            }}
                                          >
                                            {f.status}
                                          </span>
                                        </summary>
                                        <div className="border-t border-[var(--border)]/40 px-3 py-3 space-y-3 text-sm">
                                          {f.remediation_hint && (
                                            <div>
                                              <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">
                                                Summary
                                              </div>
                                              <p className="text-slate-300 leading-relaxed">{f.remediation_hint}</p>
                                            </div>
                                          )}
                                          {pb.length > 0 && (
                                            <div>
                                              <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-2">
                                                Production remediation playbook
                                              </div>
                                              <ol className="list-decimal list-inside space-y-2 text-slate-400 text-xs leading-relaxed">
                                                {pb.map((step, i) => (
                                                  <li key={i}>{step}</li>
                                                ))}
                                              </ol>
                                            </div>
                                          )}
                                          <Link
                                            href={`/dashboard/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(f.id)}`}
                                            className="inline-flex items-center gap-1 text-xs font-medium text-aws-orange hover:underline"
                                          >
                                            Open full evidence view →
                                          </Link>
                                        </div>
                                      </details>
                                    );
                                  })}
                                {pageState && pageState.loaded && pageState.total > PAGE_SIZE && (
                                  <div className="flex flex-wrap items-center justify-between gap-2 px-2 pt-2">
                                    <span className="text-[10px] text-slate-500">
                                      Page {Math.floor(pageState.skip / PAGE_SIZE) + 1} / {pagesCount} ·{" "}
                                      {pageState.total} total
                                    </span>
                                    <div className="flex gap-2">
                                      <button
                                        type="button"
                                        disabled={pageState.skip <= 0}
                                        onClick={() => void fetchGroupPage(pillar, severity, Math.max(0, pageState.skip - PAGE_SIZE))}
                                        className="text-xs rounded-md border border-[var(--border)] px-2 py-1 disabled:opacity-40 hover:bg-[var(--panel-hover)]"
                                      >
                                        Previous
                                      </button>
                                      <button
                                        type="button"
                                        disabled={pageState.skip + PAGE_SIZE >= pageState.total}
                                        onClick={() =>
                                          void fetchGroupPage(pillar, severity, pageState.skip + PAGE_SIZE)
                                        }
                                        className="text-xs rounded-md border border-[var(--border)] px-2 py-1 disabled:opacity-40 hover:bg-[var(--panel-hover)]"
                                      >
                                        Next
                                      </button>
                                    </div>
                                  </div>
                                )}
                              </div>
                            </details>
                          );
                        })}
                    </div>
                  </details>
                ))}

                {structuredGroups.some((g) => !PILLAR_ORDER.includes(g.pillar as (typeof PILLAR_ORDER)[number])) && (
                  <details className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/50">
                    <summary className="cursor-pointer px-4 py-3 text-sm text-slate-300 hover:bg-[var(--panel-hover)] list-none [&::-webkit-details-marker]:hidden">
                      Other pillars
                    </summary>
                    <div className="border-t border-[var(--border)] px-2 py-2 text-xs text-slate-500">
                      {structuredGroups
                        .filter((g) => !PILLAR_ORDER.includes(g.pillar as (typeof PILLAR_ORDER)[number]))
                        .map((g) => `${g.pillar}/${g.severity}: ${g.count}`)
                        .join(" · ")}
                    </div>
                  </details>
                )}
              </div>
            </div>
              </>
            ) : null}
          </section>
        )}
      </main>
    </div>
  );
}

export default function DashboardPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-[var(--background)] text-slate-400 flex items-center justify-center">
          Loading dashboard…
        </div>
      }
    >
      <DashboardContent />
    </Suspense>
  );
}
