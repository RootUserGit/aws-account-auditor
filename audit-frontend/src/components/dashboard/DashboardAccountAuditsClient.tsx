"use client";

import Badge from "@cloudscape-design/components/badge";
import Box from "@cloudscape-design/components/box";
import BreadcrumbGroup from "@cloudscape-design/components/breadcrumb-group";
import Button from "@cloudscape-design/components/button";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import SpaceBetween from "@cloudscape-design/components/space-between";
import {
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import dynamic from "next/dynamic";
import { useRouter, useSearchParams } from "next/navigation";
import { useTheme } from "next-themes";

import { InlineLoader } from "@/components/InlineLoader";

import {
  DashboardActiveRunHeader,
  DashboardCisComplianceCard,
  DashboardErrorBanner,
  DashboardFindingsFilterPanel,
  DashboardGroupedFindings,
  DashboardPrecheckBanner,
  DashboardRunEmptyChecksBanner,
  DashboardRunFailureBanner,
  DashboardRunLiveStatus,
  DashboardRunSummaryCards,
  DashboardSeverityStatusCharts,
} from "@/components/dashboard";
const DashboardScanHistoryTable = dynamic(
  () =>
    import("@/components/dashboard/DashboardScanHistoryTable").then(
      (m) => m.DashboardScanHistoryTable,
    ),
  {
    ssr: false,
    loading: () => (
      <div className="flex min-h-[12rem] w-full items-center justify-center rounded-[var(--border-radius-container)] border border-[var(--color-border-divider-default)] bg-[var(--color-background-container-content)] py-10">
        <InlineLoader label="Loading scan history…" size="md" />
      </div>
    ),
  },
);

import { useApi } from "@/hooks";
import { isHttpOk } from "@/lib/api/http";
import { toast } from "@/lib/toast";
import {
  DISPLAY_TZ_STORAGE_KEY,
  FINDINGS_PAGE_SIZE,
  HISTORY_PAGE_SIZE,
  PILLAR_ORDER,
  POLL_INITIAL_MS,
  POLL_MAX_MS,
  SEVERITY_ORDER,
  UUID_RE,
} from "@/lib/constants/dashboard";
import { formatEnqueueError } from "@/lib/helpers/format-enqueue-error";
import { parseApiDetail } from "@/lib/helpers/parse-api-detail";
import type {
  Account,
  FindingRow,
  PrecheckEntry,
  RunDetailState,
  ScanHistoryRow,
  StructuredGroup,
} from "@/lib/types/dashboard";
import {
  colorForCheckStatus,
  colorForSeverity,
  chartTooltipFromTheme,
  severityRank,
} from "@/lib/utils/dashboard-chart";
import { groupKey } from "@/lib/utils/dashboard-group";
import {
  normalizeAccount,
  normalizeRunDetail,
  normalizeScanHistoryRow,
} from "@/lib/utils/dashboard-normalize";
import {
  optimisticEnqueueRowId,
  readStoredDisplayTz,
} from "@/lib/utils/dashboard-time";

function AccountAuditsMainContent({
  platformAccountId,
  runId,
}: Readonly<{ platformAccountId: string; runId: string }>) {
  const router = useRouter();
  const api = useApi();
  const { resolvedTheme } = useTheme();
  const chartTips = useMemo(
    () => chartTooltipFromTheme(resolvedTheme === "light"),
    [resolvedTheme],
  );
  const pieRingStroke = resolvedTheme === "light" ? "#f2f3f3" : "#0c1117";

  const [accountRecord, setAccountRecord] = useState<Account | null>(null);
  const [accountLoading, setAccountLoading] = useState(true);
  const [accountErr, setAccountErr] = useState<string | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanHistoryRow[]>([]);
  const [scanHistoryLoading, setScanHistoryLoading] = useState(false);
  const [scanHistoryErr, setScanHistoryErr] = useState<string | null>(null);
  const [run, setRun] = useState<RunDetailState | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [refetchBusy, setRefetchBusy] = useState(false);
  const [failedOnly, setFailedOnly] = useState(true);
  const [legacySplit, setLegacySplit] = useState<{
    groups: Record<string, Record<string, number>>;
    failed_groups: Record<string, Record<string, number>>;
  } | null>(null);
  const [startingAccountId, setStartingAccountId] = useState<string | null>(
    null,
  );
  const [precheckWarnings, setPrecheckWarnings] = useState<
    PrecheckEntry[] | null
  >(null);
  const [historyPage, setHistoryPage] = useState(0);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [scanClockMs, setScanClockMs] = useState(() => Date.now());
  const [displayTz, setDisplayTz] = useState(() => readStoredDisplayTz());

  const accountReady =
    !accountLoading && Boolean(accountRecord) && !accountErr;

  const runDetailLoading =
    Boolean(runId) &&
    run === null &&
    err === null &&
    !accountErr &&
    accountReady;

  const pollBackoffRef = useRef(POLL_INITIAL_MS);
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
    return (
      activeScanAccountIds.has(platformAccountId) ||
      startingAccountId === platformAccountId
    );
  }

  /** Loaded pages per pillar|severity */
  const [pages, setPages] = useState<
    Record<
      string,
      { items: FindingRow[]; total: number; skip: number; loaded: boolean }
    >
  >({});

  const loadScanHistory = useCallback(
    async (opts?: { readonly showTableLoading?: boolean }) => {
      const showLoader = opts?.showTableLoading === true;
      if (showLoader) {
        setScanHistoryLoading(true);
        setScanHistoryErr(null);
      }
      try {
        const skip = historyPage * HISTORY_PAGE_SIZE;
        const res = await api.fetchRunsList(
          skip,
          HISTORY_PAGE_SIZE,
          platformAccountId,
        );
        const total = Number.parseInt(
          String(res.headers["x-total-count"] ?? "0"),
          10,
        );
        if (!Number.isNaN(total)) setHistoryTotal(total);
        if (!isHttpOk(res.status)) {
          if (showLoader) {
            const detail = (res.data as Record<string, unknown> | null)?.detail;
            setScanHistoryErr(
              typeof detail === "string"
                ? detail
                : res.status === 401
                  ? "API returned 401 — check audit-frontend/.env.local API key."
                  : "Could not load scan history.",
            );
          }
          return;
        }
        const rows = res.data;
        if (Array.isArray(rows)) {
          const parsed = (rows as unknown[])
            .map(normalizeScanHistoryRow)
            .filter((r): r is ScanHistoryRow => r !== null);
          setScanHistory(parsed);
        }
      } catch {
        if (showLoader) setScanHistoryErr("Could not load scan history.");
      } finally {
        if (showLoader) setScanHistoryLoading(false);
      }
    },
    [api, historyPage, platformAccountId],
  );

  useEffect(() => {
    queueMicrotask(() => {
      const maxPage = Math.max(
        0,
        Math.ceil(historyTotal / HISTORY_PAGE_SIZE) - 1,
      );
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
    let cancelled = false;
    queueMicrotask(() => {
      if (!cancelled) {
        setAccountLoading(true);
        setAccountErr(null);
        setScanHistoryErr(null);
        setScanHistory([]);
      }
    });
    api
      .getAccount(platformAccountId)
      .then((r) => {
        const data = r.data ?? null;
        if (!isHttpOk(r.status)) {
          setAccountRecord(null);
          if (!cancelled && r.status === 404) {
            setAccountErr("Account not found.");
          } else if (!cancelled) {
            setAccountErr("Failed to load account.");
          }
          return;
        }
        if (data && typeof data === "object") {
          const acc = normalizeAccount(data);
          if (acc) {
            setAccountRecord(acc);
            setAccountErr(null);
          } else {
            setAccountRecord(null);
            setAccountErr("Unexpected account response");
          }
        }
      })
      .catch(() => {
        if (!cancelled) {
          setAccountRecord(null);
          setAccountErr("Failed to load account");
        }
      })
      .finally(() => {
        if (!cancelled) setAccountLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [api, platformAccountId]);

  useEffect(() => {
    if (accountLoading) return;
    if (accountErr || !accountRecord) {
      queueMicrotask(() => {
        setScanHistoryLoading(false);
      });
      return;
    }
    queueMicrotask(() => void loadScanHistory({ showTableLoading: true }));
  }, [accountLoading, accountErr, accountRecord, loadScanHistory]);

  useEffect(() => {
    const activeRunningRow = scanHistory.some(
      (r) => (r.status?.toLowerCase() ?? "") === "running",
    );
    const activeRunningDetail =
      Boolean(runId) &&
      run &&
      (typeof run.status === "string" ? run.status.toLowerCase() : "") ===
        "running";
    if (!activeRunningRow && !activeRunningDetail) return;
    const id = globalThis.setInterval(() => setScanClockMs(Date.now()), 1000);
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

    if (!accountReady) return;

    pollBackoffRef.current = POLL_INITIAL_MS;
    let cancelled = false;
    let timeoutId: ReturnType<typeof globalThis.setTimeout> | null = null;

    const clearTimer = () => {
      if (timeoutId !== null) {
        globalThis.clearTimeout(timeoutId);
        timeoutId = null;
      }
    };

    const scheduleNextPoll = () => {
      if (cancelled) return;
      const wait = pollBackoffRef.current;
      pollBackoffRef.current = Math.min(POLL_MAX_MS, Math.floor(wait * 1.45));
      timeoutId = globalThis.setTimeout(() => {
        void tick();
      }, wait);
    };

    const isRunFinished = (data: Record<string, unknown>): boolean => {
      const raw = data.status;
      const normalized =
        typeof raw === "string" ? raw.trim().toLowerCase() : "";
      if (
        normalized === "succeeded" ||
        normalized === "failed" ||
        normalized === "cancelled"
      )
        return true;
      if (data.finished_at != null && data.finished_at !== "") return true;
      return false;
    };

    const tick = async () => {
      if (cancelled) return;
      let finished = false;
      try {
        const res = await api.fetchRun(runId);
        const data = (res.data ?? null) as Record<string, unknown> | null;
        if (cancelled || !isHttpOk(res.status) || !data) {
          if (!cancelled && runId && !isHttpOk(res.status))
            setErr("Run not found or inaccessible.");
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
  }, [api, runId, loadScanHistory, accountReady]);

  /** Legacy runs: derive groups once from a capped fetch (counts only — details stay behind accordions). */
  useEffect(() => {
    if (!runId || run?.status !== "succeeded" || run.summary_json?.groups) {
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const res = await api.fetchRunFindingsCapped(runId, 400);
        if (!isHttpOk(res.status)) return;
        const rows = (Array.isArray(res.data) ? res.data : []) as FindingRow[];
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
  }, [api, runId, run?.status, run?.summary_json?.groups]);

  useEffect(() => {
    queueMicrotask(() => {
      setPages({});
    });
  }, [runId, failedOnly]);

  async function cancelScan(targetRunId: string) {
    try {
      const res = await api.postCancelRun(targetRunId);
      if (!isHttpOk(res.status)) {
        const data = (res.data ?? {}) as { detail?: unknown };
        const msg = parseApiDetail(data.detail);
        setErr(msg === "Request failed" ? "Could not cancel scan" : msg);
        toast.error(msg === "Request failed" ? "Could not cancel scan" : msg);
        return;
      }
      setErr(null);
      toast.success("Scan cancelled");
      await loadScanHistory();
      if (runId === targetRunId) {
        try {
          const rr = await api.fetchRun(targetRunId);
          const payload = (rr.data ?? null) as Record<string, unknown> | null;
          const parsed = normalizeRunDetail(payload);
          if (isHttpOk(rr.status) && parsed) setRun(parsed);
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
      toast.error("Could not cancel scan");
    }
  }

  async function startRun() {
    const platformAccountUuid = platformAccountId;
    if (enqueueInflightRef.current.has(platformAccountUuid)) return;
    if (activeScanAccountIds.has(platformAccountUuid)) {
      setErr(
        "This account already has a queued or running audit. Wait for it to finish.",
      );
      return;
    }
    const pendId = optimisticEnqueueRowId(platformAccountUuid);
    const acc = accountRecord;
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
      const res = await api.postAccountRuns(platformAccountUuid);
      const data = (res.data ?? {}) as Record<string, unknown>;
      if (!isHttpOk(res.status)) {
        dropPending();
        setPrecheckWarnings(null);
        const msg = formatEnqueueError(data);
        setErr(msg);
        toast.error(msg);
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
        toast.error("No run_id returned");
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
      router.replace(
        `/dashboard/accounts/${encodeURIComponent(platformAccountId)}?run=${encodeURIComponent(id)}`,
      );
      await loadScanHistory();
      toast.success("Audit queued");
    } catch {
      dropPending();
      setErr("Could not start audit — network error.");
      toast.error("Could not start audit — network error.");
    } finally {
      enqueueInflightRef.current.delete(platformAccountUuid);
      setStartingAccountId(null);
    }
  }

  function openRun(id: string) {
    router.replace(
      `/dashboard/accounts/${encodeURIComponent(platformAccountId)}?run=${encodeURIComponent(id)}`,
    );
  }

  function clearRunView() {
    router.replace(
      `/dashboard/accounts/${encodeURIComponent(platformAccountId)}`,
    );
    setErr(null);
    setPrecheckWarnings(null);
  }

  async function manualRefetch() {
    if (!runId) return;
    setRefetchBusy(true);
    try {
      const res = await api.fetchRun(runId);
      const data = (res.data ?? null) as Record<string, unknown> | null;
      if (!isHttpOk(res.status) || !data) {
        setErr("Could not refetch run");
        toast.error("Could not refetch run");
        return;
      }
      const parsed = normalizeRunDetail(data);
      if (parsed) setRun(parsed);
      setErr(null);
      setPages({});
      void loadScanHistory();
      toast.success("Run refreshed");
    } finally {
      setRefetchBusy(false);
    }
  }

  async function fetchGroupPage(
    pillar: string,
    severity: string,
    skip: number,
  ) {
    const key = groupKey(pillar, severity);
    const params = new URLSearchParams({
      pillar,
      severity,
      skip: String(skip),
      limit: String(FINDINGS_PAGE_SIZE),
    });
    if (failedOnly) params.set("status", "failed");
    const res = await api.fetchRunFindings(runId, params);
    const total = Number.parseInt(
      String(res.headers["x-total-count"] ?? "0"),
      10,
    );
    const items = (Array.isArray(res.data) ? res.data : []) as FindingRow[];
    setPages((prev) => ({
      ...prev,
      [key]: {
        items: Array.isArray(items) ? items : [],
        total,
        skip,
        loaded: true,
      },
    }));
  }

  function onGroupToggle(open: boolean, pillar: string, severity: string) {
    const key = groupKey(pillar, severity);
    if (!open || !runId) return;
    setPages((prev) => {
      if (prev[key]?.loaded) return prev;
      return {
        ...prev,
        [key]: { items: [], total: 0, skip: 0, loaded: false },
      };
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
  const mergedFailedGroups =
    summary?.failed_groups ?? legacySplit?.failed_groups;

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

  const structuredGroups = useMemo((): StructuredGroup[] => {
    const out: StructuredGroup[] = [];
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
      if (mergedGroups?.[pillar])
        Object.keys(mergedGroups[pillar]).forEach((s) => severities.add(s));
      if (mergedFailedGroups?.[pillar])
        Object.keys(mergedFailedGroups[pillar]).forEach((s) =>
          severities.add(s),
        );
      const ordered = [
        ...SEVERITY_ORDER.filter((s) => severities.has(s)),
        ...[...severities].filter(
          (s) => !SEVERITY_ORDER.includes(s as (typeof SEVERITY_ORDER)[number]),
        ),
      ];
      for (const severity of ordered) {
        const n = countInGroup(pillar, severity);
        if (n > 0) out.push({ pillar, severity, count: n });
      }
    }
    return out;
  }, [mergedGroups, mergedFailedGroups, failedOnly]);

  const onBreadcrumbFollow = useCallback(
    (event: CustomEvent) => {
      event.preventDefault();
      const href = (event.detail as { href?: string }).href;
      if (href) router.push(href);
    },
    [router],
  );

  return (
    <ContentLayout
      breadcrumbs={
        <BreadcrumbGroup
          items={[
            { text: "Welcome", href: "/" },
            { text: "Operations dashboard", href: "/dashboard" },
            {
              text:
                accountRecord?.display_name ??
                (accountLoading ? "Loading…" : "Account"),
              href: `/dashboard/accounts/${encodeURIComponent(platformAccountId)}`,
            },
          ]}
          onFollow={onBreadcrumbFollow}
        />
      }
      maxContentWidth={1440}
      header={
        <Header variant="h1" description="Scan history and findings for this AWS account. Start a run, then open it from the table or the run panel below.">
          Account audits
        </Header>
      }
    >
      <div className="dashboard-tailwind-surface">
        <SpaceBetween size="xl" direction="vertical">
          {accountErr ? (
            <DashboardErrorBanner message={accountErr} />
          ) : null}
          {err ? <DashboardErrorBanner message={err} /> : null}

          {precheckWarnings && precheckWarnings.length > 0 ? (
            <DashboardPrecheckBanner
              entries={precheckWarnings}
              onDismiss={() => setPrecheckWarnings(null)}
            />
          ) : null}

          <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[var(--color-border-divider-default)] pb-4">
            <div className="space-y-1 min-w-0">
              {accountLoading ? (
                <InlineLoader label="Loading account…" size="sm" />
              ) : (
                <>
                  <Box variant="h2" margin={{ bottom: "xs" }}>
                    {accountRecord?.display_name ?? "—"}
                  </Box>
                  <Box fontSize="body-s" color="text-body-secondary">
                    AWS account{" "}
                    <Box variant="code" fontSize="body-s">
                      {accountRecord?.account_id ?? "—"}
                    </Box>
                  </Box>
                  {accountRecord?.environment ? (
                    <Box margin={{ top: "xs" }}>
                      <Badge color="grey">
                        {accountRecord.environment.trim().toLowerCase()}
                      </Badge>
                    </Box>
                  ) : null}
                </>
              )}
            </div>
            <Button
              variant="primary"
              formAction="none"
              disabled={
                accountLoading ||
                Boolean(accountErr) ||
                accountScanBlocked(platformAccountId)
              }
              loading={startingAccountId === platformAccountId}
              onClick={() => void startRun()}
            >
              Start audit run
            </Button>
          </div>

          {accountErr && !accountLoading ? (
            <Button
              formAction="none"
              onClick={() => router.push("/dashboard")}
            >
              Back to operations dashboard
            </Button>
          ) : null}

          {accountLoading ? null : accountErr ? null : (
            <>
              {scanHistoryErr ? (
                <DashboardErrorBanner message={scanHistoryErr} />
              ) : null}

              <DashboardScanHistoryTable
                scanHistory={scanHistory}
                runId={runId}
                scanClockMs={scanClockMs}
                displayTz={displayTz}
                onDisplayTzChange={persistDisplayTz}
                onRefresh={() =>
                  void loadScanHistory({ showTableLoading: true })
                }
                historyPage={historyPage}
                historyTotal={historyTotal}
                onHistoryPageChange={setHistoryPage}
                onCancelScan={(targetRunId: string) =>
                  void cancelScan(targetRunId)
                }
                onOpenRun={openRun}
                loading={scanHistoryLoading}
              />
            </>
          )}

          {accountReady && runId ? (
            <section className="space-y-6">
              <DashboardActiveRunHeader
                runId={runId}
                run={run}
                terminal={terminal}
                scanClockMs={scanClockMs}
                refetchBusy={refetchBusy}
                detailLoading={runDetailLoading}
                onRefresh={() => void manualRefetch()}
                onCancelRun={() => void cancelScan(runId)}
                onClosePanel={clearRunView}
              />

              <DashboardRunLiveStatus
                run={run}
                terminal={terminal}
                runProgress={runProgress}
              />

              {terminalRunUnsuccessful ? (
                <DashboardRunFailureBanner run={run} />
              ) : null}

              <DashboardRunEmptyChecksBanner
                terminal={terminal}
                run={run}
                summary={summary}
              />

              {terminalRunUnsuccessful ? null : (
                <>
                  <DashboardFindingsFilterPanel
                    failedOnly={failedOnly}
                    onToggle={() => setFailedOnly((v) => !v)}
                  />

                  <DashboardCisComplianceCard
                    cis={summary?.cis_aws_foundations_v15}
                  />

                  {summary ? (
                    <DashboardRunSummaryCards summary={summary} />
                  ) : null}

                  <DashboardSeverityStatusCharts
                    sevData={sevData}
                    stData={stData}
                    chartTips={chartTips}
                    pieRingStroke={pieRingStroke}
                    isLight={resolvedTheme === "light"}
                  />

                  <DashboardGroupedFindings
                    runId={runId}
                    run={run}
                    terminal={terminal}
                    mergedGroups={mergedGroups}
                    failedOnly={failedOnly}
                    structuredGroups={structuredGroups}
                    pages={pages}
                    onGroupToggle={onGroupToggle}
                    onFetchGroupPage={(pillar, severity, skip) => {
                      void fetchGroupPage(pillar, severity, skip);
                    }}
                  />
                </>
              )}
            </section>
          ) : null}
        </SpaceBetween>
      </div>
    </ContentLayout>
  );
}

function AccountAuditsRouteFallback({
  platformAccountId,
}: Readonly<{ platformAccountId: string }>) {
  return (
    <ContentLayout
      breadcrumbs={
        <BreadcrumbGroup
          items={[
            { text: "Welcome", href: "/" },
            { text: "Operations dashboard", href: "/dashboard" },
            {
              text: "Account",
              href: `/dashboard/accounts/${encodeURIComponent(platformAccountId)}`,
            },
          ]}
        />
      }
      maxContentWidth={1440}
      header={
        <Header
          variant="h1"
          description="Scan history and findings for this AWS account."
        >
          Account audits
        </Header>
      }
    >
      <div className="flex min-h-[200px] items-center justify-center py-16">
        <InlineLoader label="Loading…" size="md" />
      </div>
    </ContentLayout>
  );
}

function AccountAuditsWithSearchParams({
  platformAccountId,
}: Readonly<{ platformAccountId: string }>) {
  const searchParams = useSearchParams();
  const runParam = searchParams.get("run")?.trim() ?? "";
  const runId = UUID_RE.test(runParam) ? runParam : "";
  return (
    <AccountAuditsMainContent
      platformAccountId={platformAccountId}
      runId={runId}
    />
  );
}

export function DashboardAccountAuditsClient({
  platformAccountId,
}: Readonly<{ platformAccountId: string }>) {
  return (
    <Suspense
      fallback={
        <AccountAuditsRouteFallback platformAccountId={platformAccountId} />
      }
    >
      <AccountAuditsWithSearchParams platformAccountId={platformAccountId} />
    </Suspense>
  );
}
