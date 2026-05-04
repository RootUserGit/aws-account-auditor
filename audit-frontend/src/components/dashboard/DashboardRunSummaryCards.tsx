"use client";

import type { RunSummary } from "@/lib/types/dashboard";

export type DashboardRunSummaryCardsProps = {
  readonly summary: RunSummary;
};

export function DashboardRunSummaryCards({
  summary,
}: DashboardRunSummaryCardsProps) {
  return (
    <div className="space-y-2">
      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/60 p-4">
          <div className="text-[10px] uppercase tracking-widest dash-text-subtle">
            Checks evaluated
          </div>
          <div className="text-2xl font-semibold dash-text-primary mt-1">
            {summary.total ?? "—"}
          </div>
        </div>
        <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/60 p-4">
          <div className="text-[10px] uppercase tracking-widest dash-text-subtle">
            Failed
          </div>
          <div className="text-2xl font-semibold text-red-600 dark:text-red-400 mt-1">
            {summary.by_status?.failed ?? "—"}
          </div>
        </div>
        <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/60 p-4">
          <div className="text-[10px] uppercase tracking-widest dash-text-subtle">
            Passed
          </div>
          <div className="text-2xl font-semibold text-emerald-700 dark:text-emerald-400 mt-1">
            {summary.by_status?.passed ?? "—"}
          </div>
        </div>
        <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/60 p-4">
          <div className="text-[10px] uppercase tracking-widest dash-text-subtle">
            Unknown
          </div>
          <div className="text-2xl font-semibold text-amber-800 dark:text-amber-200/95 mt-1 tabular-nums">
            {summary.by_status?.unknown ?? "—"}
          </div>
        </div>
      </div>
      <p className="text-xs dash-text-muted leading-relaxed max-w-3xl">
        <span className="dash-text-secondary">Unknown</span> means the rule
        could not decide pass/fail — usually missing read permissions, empty
        inventory for that service in the sampled Regions, or a worker that is
        behind the rule pack (shows as{" "}
        <code className="dash-text-secondary font-mono text-[11px]">
          unknown_evaluator:…
        </code>{" "}
        in evidence). Rebuild and restart{" "}
        <span className="font-mono dash-text-secondary">audit-worker</span>{" "}
        after pulling new rules.
      </p>
    </div>
  );
}
