"use client";

import { Suspense, useCallback, useEffect, useState } from "react";
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
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const CHART_TOOLTIP = {
  contentStyle: {
    backgroundColor: "#1e293b",
    border: "1px solid #334155",
    borderRadius: "6px",
  },
  labelStyle: { color: "#e2e8f0" },
  itemStyle: { color: "#cbd5e1" },
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function severityRank(name: string): number {
  const i = SEVERITY_ORDER.indexOf(name.toLowerCase() as (typeof SEVERITY_ORDER)[number]);
  return i === -1 ? 99 : i;
}

function colorForSeverity(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "#dc2626";
    case "high":
      return "#ea580c";
    case "medium":
      return "#ca8a04";
    case "low":
      return "#2563eb";
    case "info":
      return "#64748b";
    default:
      return "#94a3b8";
  }
}

function colorForCheckStatus(status: string): string {
  switch (status.toLowerCase()) {
    case "passed":
      return "#059669";
    case "failed":
      return "#dc2626";
    case "unknown":
      return "#d97706";
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
  status: string;
  rule_pack_version: string;
  error_code: string | null;
  started_at: string | null;
  finished_at: string | null;
};

function fmtWhen(iso: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function DashboardContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const runParam = searchParams.get("run")?.trim() ?? "";
  const runId = UUID_RE.test(runParam) ? runParam : "";

  const [accounts, setAccounts] = useState<Account[]>([]);
  const [scanHistory, setScanHistory] = useState<ScanHistoryRow[]>([]);
  const [run, setRun] = useState<{
    status: string;
    summary_json: Record<string, unknown> | null;
  } | null>(null);
  const [findings, setFindings] = useState<
    {
      id: string;
      severity: string;
      status: string;
      check_id: string;
      pillar: string;
      remediation_hint?: string | null;
    }[]
  >([]);
  const [err, setErr] = useState<string | null>(null);
  const [refetchBusy, setRefetchBusy] = useState(false);

  const loadScanHistory = useCallback(async () => {
    try {
      const res = await fetch("/api/backend/runs?limit=50", { cache: "no-store" });
      if (!res.ok) return;
      const rows = await res.json();
      if (Array.isArray(rows)) setScanHistory(rows as ScanHistoryRow[]);
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    fetch("/api/backend/accounts")
      .then((r) => r.json())
      .then(setAccounts)
      .catch(() => setErr("Failed to load accounts"));
  }, []);

  useEffect(() => {
    void loadScanHistory();
  }, [loadScanHistory]);

  useEffect(() => {
    if (!runId) {
      setRun(null);
      setFindings([]);
      return;
    }

    let cancelled = false;
    let timeoutId: number | null = null;

    const clearTimer = () => {
      if (timeoutId !== null) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }
    };

    const isRunFinished = (data: Record<string, unknown>): boolean => {
      const raw = data.status;
      const normalized =
        typeof raw === "string" ? raw.trim().toLowerCase() : "";
      if (normalized === "succeeded" || normalized === "failed") return true;
      if (data.finished_at != null && data.finished_at !== "") return true;
      return false;
    };

    const tick = async () => {
      if (cancelled) return;
      let finished = false;
      try {
        const res = await fetch(`/api/backend/runs/${runId}`, {
          cache: "no-store",
        });
        const data = (await res.json().catch(() => null)) as Record<
          string,
          unknown
        > | null;
        if (cancelled || !res.ok || !data) {
          if (!cancelled && runId && !res.ok) {
            setErr("Run not found or inaccessible.");
          }
          return;
        }

        finished = isRunFinished(data);

        const statusStr =
          typeof data.status === "string" ? data.status : String(data.status ?? "");

        setRun({
          status: statusStr,
          summary_json: (data.summary_json as Record<string, unknown> | null) ?? null,
        });
        setErr(null);

        const fr = await fetch(`/api/backend/runs/${runId}/findings?limit=500`, {
          cache: "no-store",
        });
        const rows = await fr.json().catch(() => []);
        if (cancelled) return;
        setFindings(Array.isArray(rows) ? rows : []);

        if (finished) void loadScanHistory();
      } catch {
        /* retry later */
      }

      if (cancelled || finished) return;
      timeoutId = window.setTimeout(() => {
        void tick();
      }, 2000);
    };

    void tick();

    return () => {
      cancelled = true;
      clearTimer();
    };
  }, [runId, loadScanHistory]);

  async function startRun(platformAccountUuid: string) {
    setErr(null);
    const res = await fetch(`/api/backend/accounts/${platformAccountUuid}/runs`, {
      method: "POST",
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      setErr(typeof data.detail === "string" ? data.detail : "Run failed");
      return;
    }
    const id = typeof data.run_id === "string" ? data.run_id : "";
    if (!id) {
      setErr("No run_id returned");
      return;
    }
    router.replace(`/dashboard?run=${encodeURIComponent(id)}`);
    void loadScanHistory();
  }

  function openRun(id: string) {
    router.replace(`/dashboard?run=${encodeURIComponent(id)}`);
  }

  function clearRunView() {
    router.replace("/dashboard");
    setErr(null);
  }

  async function manualRefetch() {
    if (!runId) return;
    setRefetchBusy(true);
    try {
      const res = await fetch(`/api/backend/runs/${runId}`, { cache: "no-store" });
      const data = (await res.json().catch(() => null)) as Record<
        string,
        unknown
      > | null;
      if (!res.ok || !data) {
        setErr("Could not refetch run");
        return;
      }
      setRun({
        status: typeof data.status === "string" ? data.status : String(data.status ?? ""),
        summary_json: (data.summary_json as Record<string, unknown> | null) ?? null,
      });
      const fr = await fetch(`/api/backend/runs/${runId}/findings?limit=500`, {
        cache: "no-store",
      });
      const rows = await fr.json().catch(() => []);
      setFindings(Array.isArray(rows) ? rows : []);
      setErr(null);
      void loadScanHistory();
    } finally {
      setRefetchBusy(false);
    }
  }

  const sevCounts: Record<string, number> = {};
  for (const f of findings) {
    sevCounts[f.severity] = (sevCounts[f.severity] ?? 0) + 1;
  }
  const sevData = Object.entries(sevCounts)
    .map(([name, value]) => ({
      name,
      value,
      fill: colorForSeverity(name),
    }))
    .sort((a, b) => severityRank(a.name) - severityRank(b.name));

  const stCounts: Record<string, number> = {};
  for (const f of findings) {
    stCounts[f.status] = (stCounts[f.status] ?? 0) + 1;
  }
  const STATUS_ORDER = ["failed", "passed", "unknown"];
  function statusRank(name: string): number {
    const i = STATUS_ORDER.indexOf(name.toLowerCase());
    return i === -1 ? 99 : i;
  }
  const stData = Object.entries(stCounts)
    .map(([name, value]) => ({
      name,
      value,
      fill: colorForCheckStatus(name),
    }))
    .sort((a, b) => statusRank(a.name) - statusRank(b.name));

  const terminal =
    run?.status === "succeeded" || run?.status === "failed";

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 p-8">
      <div className="max-w-6xl mx-auto space-y-10">
        <div className="flex flex-wrap justify-between items-start gap-4">
          <div>
            <Link href="/" className="text-emerald-400 text-sm hover:underline">
              ← Home
            </Link>
            <h1 className="text-2xl font-semibold mt-2">Dashboard</h1>
            <p className="text-xs text-slate-500 mt-1">
              Open scans from history below; the URL keeps{" "}
              <code className="text-slate-400">?run=…</code> so refresh restores the
              same report.
            </p>
          </div>
          <div className="flex flex-wrap gap-2 items-center">
            {runId && (
              <>
                <a
                  href={`/api/backend/runs/${runId}/report.html`}
                  className="text-sm text-emerald-400 hover:underline"
                  target="_blank"
                  rel="noreferrer"
                >
                  Open HTML report
                </a>
                <button
                  type="button"
                  onClick={() => void manualRefetch()}
                  disabled={refetchBusy}
                  className="text-sm rounded-md border border-slate-600 px-3 py-1.5 hover:bg-slate-800 disabled:opacity-50"
                >
                  {refetchBusy ? "Refetching…" : "Refetch data"}
                </button>
                <button
                  type="button"
                  onClick={clearRunView}
                  className="text-sm rounded-md border border-slate-600 px-3 py-1.5 hover:bg-slate-800"
                >
                  Close scan view
                </button>
              </>
            )}
          </div>
        </div>

        {err && (
          <p className="text-red-400 text-sm border border-red-900 rounded-md p-3">{err}</p>
        )}

        <section className="space-y-3">
          <div className="flex flex-wrap justify-between items-center gap-2">
            <h2 className="font-medium text-slate-300">Scan history</h2>
            <button
              type="button"
              onClick={() => void loadScanHistory()}
              className="text-xs text-emerald-400 hover:underline"
            >
              Refresh list
            </button>
          </div>
          <div className="overflow-x-auto rounded-lg border border-slate-800">
            <table className="min-w-full text-sm">
              <thead className="bg-slate-900">
                <tr>
                  <th className="text-left p-2">AWS account</th>
                  <th className="text-left p-2">Run status</th>
                  <th className="text-left p-2">Started</th>
                  <th className="text-left p-2">Finished</th>
                  <th className="text-left p-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {scanHistory.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="p-4 text-slate-500 text-center">
                      No runs yet — start an audit from an account below.
                    </td>
                  </tr>
                ) : (
                  scanHistory.map((row) => {
                    const active = row.id === runId;
                    return (
                      <tr
                        key={row.id}
                        className={`border-t border-slate-800 ${active ? "bg-emerald-950/25" : "hover:bg-slate-900/80"}`}
                      >
                        <td className="p-2 font-mono text-xs">{row.aws_account_id}</td>
                        <td className="p-2 capitalize">{row.status}</td>
                        <td className="p-2 text-slate-400 text-xs">{fmtWhen(row.started_at)}</td>
                        <td className="p-2 text-slate-400 text-xs">{fmtWhen(row.finished_at)}</td>
                        <td className="p-2 flex flex-wrap gap-2">
                          <button
                            type="button"
                            onClick={() => openRun(row.id)}
                            className="text-emerald-400 hover:underline text-xs"
                          >
                            View
                          </button>
                          <button
                            type="button"
                            onClick={() => void startRun(row.platform_account_id)}
                            className="text-slate-300 hover:underline text-xs"
                          >
                            Re-scan
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="font-medium text-slate-300">Accounts</h2>
          <div className="grid gap-3 md:grid-cols-2">
            {accounts.map((a) => (
              <div
                key={a.id}
                className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 flex flex-col gap-2"
              >
                <div className="text-sm text-slate-400">{a.account_id}</div>
                <div className="text-xs truncate text-slate-500">{a.role_arn}</div>
                <div className="text-xs">Status: {a.status}</div>
                {a.status === "error" && a.last_verify_error_code && (
                  <div className="text-xs text-amber-400 font-mono">
                    Last STS error: {a.last_verify_error_code}
                  </div>
                )}
                <button
                  type="button"
                  onClick={() => void startRun(a.id)}
                  className="mt-2 rounded-md bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-medium text-sm py-1.5"
                >
                  Start audit run
                </button>
              </div>
            ))}
          </div>
        </section>

        {runId && (
          <section className="space-y-4">
            <h2 className="font-medium text-slate-300">
              Run <code className="text-emerald-300">{runId}</code>
            </h2>
            <p className="text-sm text-slate-400">
              Worker status: {run?.status ?? "…"}
              {terminal ? (
                <span className="ml-2 text-slate-500">(polling stopped)</span>
              ) : (
                <span className="ml-2 text-amber-400/90">(updating…)</span>
              )}
            </p>
            {run?.summary_json && (
              <pre className="text-xs bg-slate-900 border border-slate-800 rounded-md p-3 overflow-auto">
                {JSON.stringify(run.summary_json, null, 2)}
              </pre>
            )}
            <div className="grid md:grid-cols-2 gap-8 h-64">
              <div>
                <h3 className="text-sm text-slate-400 mb-2">By severity</h3>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={sevData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      label={{ fill: "#e2e8f0", fontSize: 11 }}
                    >
                      {sevData.map((entry, i) => (
                        <Cell key={`${entry.name}-${i}`} fill={entry.fill} />
                      ))}
                    </Pie>
                    <Tooltip {...CHART_TOOLTIP} />
                    <Legend
                      wrapperStyle={{ color: "#cbd5e1" }}
                      formatter={(value) => (
                        <span className="text-slate-300 capitalize">{value}</span>
                      )}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div>
                <h3 className="text-sm text-slate-400 mb-2">By check status</h3>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={stData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis dataKey="name" stroke="#94a3b8" />
                    <YAxis stroke="#94a3b8" />
                    <Tooltip {...CHART_TOOLTIP} />
                    <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                      {stData.map((entry, i) => (
                        <Cell key={`${entry.name}-${i}`} fill={entry.fill} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="min-w-full text-sm">
                <thead className="bg-slate-900">
                  <tr>
                    <th className="text-left p-2">Check</th>
                    <th className="text-left p-2">Pillar</th>
                    <th className="text-left p-2">Severity</th>
                    <th className="text-left p-2">Status</th>
                    <th className="text-left p-2">Remediation</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f) => (
                    <tr key={f.id} className="border-t border-slate-800 hover:bg-slate-900/80">
                      <td className="p-2 font-mono text-xs">
                        <Link
                          href={`/dashboard/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(f.id)}`}
                          className="text-emerald-400 hover:underline"
                        >
                          {f.check_id}
                        </Link>
                      </td>
                      <td className="p-2 text-slate-300">{f.pillar}</td>
                      <td className="p-2">
                        <span
                          className="inline-block rounded px-2 py-0.5 text-xs font-medium capitalize border"
                          style={{
                            color: colorForSeverity(f.severity),
                            borderColor: `${colorForSeverity(f.severity)}66`,
                            backgroundColor: `${colorForSeverity(f.severity)}18`,
                          }}
                        >
                          {f.severity}
                        </span>
                      </td>
                      <td className="p-2">
                        <span
                          className="inline-block rounded px-2 py-0.5 text-xs font-medium capitalize border"
                          style={{
                            color: colorForCheckStatus(f.status),
                            borderColor: `${colorForCheckStatus(f.status)}66`,
                            backgroundColor: `${colorForCheckStatus(f.status)}18`,
                          }}
                        >
                          {f.status}
                        </span>
                      </td>
                      <td className="p-2 text-slate-400 text-xs max-w-md">
                        {f.remediation_hint ?? "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}
      </div>
    </main>
  );
}

export default function DashboardPage() {
  return (
    <Suspense
      fallback={
        <main className="min-h-screen bg-slate-950 text-slate-400 p-8">
          Loading dashboard…
        </main>
      }
    >
      <DashboardContent />
    </Suspense>
  );
}
