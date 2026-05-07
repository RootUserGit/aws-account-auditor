"use client";

import type { RunDetailState, RunSummary } from "@/lib/types/dashboard";

export type DashboardRunFailureBannerProps = {
  readonly run: RunDetailState | null;
};

export function DashboardRunFailureBanner({
  run,
}: DashboardRunFailureBannerProps) {
  if (!run) return null;
  const st = run.status?.toLowerCase() ?? "";
  if (st !== "failed" && st !== "cancelled") return null;

  const failed = st === "failed";

  return (
    <div
      className={`flex flex-wrap items-start gap-4 rounded-xl border px-4 py-4 ${
        failed
          ? "border-red-300 dark:border-red-900/45 bg-red-50 dark:bg-red-950/20"
          : "border-amber-300 dark:border-amber-800/40 bg-amber-50 dark:bg-amber-950/15"
      }`}
      role="alert"
    >
      <span
        className={`inline-block h-10 w-10 shrink-0 rounded-full border-2 mt-0.5 ${
          failed
            ? "border-red-500/60 bg-red-100 dark:bg-red-500/10"
            : "border-amber-500/50 bg-amber-100 dark:bg-amber-500/10"
        }`}
        aria-hidden
      />
      <div className="min-w-0 flex-1 space-y-2">
        <p
          className={`text-sm font-semibold tracking-tight ${
            failed
              ? "text-red-800 dark:text-red-200"
              : "text-amber-900 dark:text-amber-100"
          }`}
        >
          {failed ? "Scan failed" : "Scan cancelled"}
        </p>
        {run.error_code ? (
          <p className="text-xs font-mono dash-text-muted">
            <span className="dash-text-subtle">Error code: </span>
            {run.error_code}
          </p>
        ) : null}
        {run.error_summary ? (
          <pre className="text-xs dash-text-secondary whitespace-pre-wrap break-words leading-relaxed rounded-md border border-[var(--border)] bg-[var(--panel)] px-3 py-2.5">
            {run.error_summary}
          </pre>
        ) : (
          <p className="text-xs dash-text-muted leading-relaxed">
            No detailed failure message was stored for this run. Use{" "}
            <span className="dash-text-secondary">Refresh</span> after the
            worker finishes writing status, or check worker logs if this
            persists.
          </p>
        )}
        {run.summary_json &&
        typeof run.summary_json === "object" &&
        run.summary_json !== null &&
        Object.keys(run.summary_json).length > 0 ? (
          <details className="rounded-md border border-[var(--border)] bg-[var(--panel)] mt-1">
            <summary className="cursor-pointer text-xs dash-text-muted hover:dash-text-secondary px-3 py-2 select-none">
              Technical details (raw summary JSON)
            </summary>
            <pre className="text-[11px] dash-text-muted whitespace-pre-wrap break-words px-3 pb-3 pt-0 font-mono leading-relaxed max-h-72 overflow-auto border-t border-[var(--border)]">
              {JSON.stringify(run.summary_json, null, 2)}
            </pre>
          </details>
        ) : null}
      </div>
    </div>
  );
}

export type DashboardRunEmptyChecksBannerProps = {
  readonly terminal: boolean;
  readonly run: RunDetailState | null;
  readonly summary: RunSummary | null | undefined;
};

export function DashboardRunEmptyChecksBanner({
  terminal,
  run,
  summary,
}: DashboardRunEmptyChecksBannerProps) {
  if (
    !terminal ||
    run?.status !== "succeeded" ||
    summary == null ||
    (summary.total ?? 0) !== 0
  ) {
    return null;
  }

  return (
    <output
      className="flex flex-wrap items-start gap-3 rounded-xl border border-amber-600/40 dark:border-amber-800/45 bg-amber-50 dark:bg-amber-950/25 px-4 py-3"
      aria-live="polite"
    >
      <div className="min-w-0 flex-1 space-y-1">
        <p className="text-sm font-medium text-amber-900 dark:text-amber-100/95">
          No checks were evaluated
        </p>
        <p className="text-xs dash-text-muted leading-relaxed">
          This usually means the worker could not find any rule YAML under{" "}
          <span className="font-mono dash-text-secondary">RULE_PACK_PATH</span>.
          Fix the worker environment, rebuild the worker image so{" "}
          <span className="font-mono dash-text-secondary">rule_packs/v1</span>{" "}
          is present, and run a new scan — charts and the HTML report stay empty
          when the rule pack resolves to zero files.
        </p>
      </div>
    </output>
  );
}
