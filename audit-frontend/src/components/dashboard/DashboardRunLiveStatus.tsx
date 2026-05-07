"use client";

import { POLL_INITIAL_MS, POLL_MAX_MS } from "@/lib/constants/dashboard";
import type { RunDetailState, RunProgress } from "@/lib/types/dashboard";

export type DashboardRunLiveStatusProps = {
  readonly run: RunDetailState | null;
  readonly terminal: boolean;
  readonly runProgress: RunProgress | undefined;
};

function phaseLabel(phase: string) {
  return phase.replaceAll("_", " ");
}

export function DashboardRunLiveStatus({
  run,
  terminal,
  runProgress,
}: DashboardRunLiveStatusProps) {
  const st = run?.status?.toLowerCase() ?? "";
  if (terminal) return null;

  if (st === "queued") {
    return (
      <output
        className="flex flex-wrap items-start gap-4 rounded-xl border border-amber-600/35 dark:border-amber-700/40 bg-amber-50/80 dark:from-amber-950/40 dark:bg-gradient-to-r dark:to-transparent px-4 py-4"
        aria-live="polite"
      >
        <span
          className="inline-block h-10 w-10 shrink-0 rounded-full border-2 border-amber-500/50 mt-0.5"
          aria-hidden
        />
        <div className="min-w-0 flex-1 space-y-1">
          <p className="text-sm font-semibold text-amber-900 dark:text-amber-100/95 tracking-tight">
            Run queued
          </p>
          <p className="text-xs dash-text-muted leading-relaxed">
            The audit has not started executing yet. Work runs in worker
            processes, not in your browser. This page polls status on an
            interval from ~{POLL_INITIAL_MS / 1000}s up to ~{POLL_MAX_MS / 1000}
            s. Avoid starting another scan for the same account until this run
            leaves the queue or finishes.
          </p>
          {runProgress?.phase ? (
            <details className="mt-2 rounded-md border border-amber-200 dark:border-amber-800/35 bg-white/60 dark:bg-black/20">
              <summary className="cursor-pointer text-xs text-amber-900 dark:text-amber-200/90 px-2 py-2 select-none">
                Scan progress
              </summary>
              <div className="px-2 pb-2 pt-0 text-xs dash-text-muted space-y-1">
                <p className="font-mono capitalize">
                  {phaseLabel(runProgress.phase)}
                </p>
                {runProgress.message ? (
                  <p className="dash-text-subtle">{runProgress.message}</p>
                ) : null}
              </div>
            </details>
          ) : null}
        </div>
      </output>
    );
  }

  if (st !== "running") return null;

  return (
    <output
      className="flex flex-wrap items-start gap-4 rounded-xl border border-aws-orange/35 bg-gradient-to-r from-aws-orange/10 dark:from-aws-orange/15 to-transparent px-4 py-4"
      aria-live="polite"
    >
      <span
        className="inline-block h-10 w-10 shrink-0 rounded-full border-2 border-aws-orange border-t-transparent animate-spin mt-0.5"
        aria-hidden
      />
      <div className="min-w-0 flex-1 space-y-1">
        <p className="text-sm font-semibold dash-text-primary tracking-tight">
          Audit running
        </p>
        <p className="text-xs dash-text-muted leading-relaxed">
          Data collection and rule evaluation run in the audit worker — not in
          your browser. This page polls run status on an interval that starts
          around {POLL_INITIAL_MS / 1000}s and gradually increases (cap ~
          {POLL_MAX_MS / 1000}s). You can leave this tab open; avoid starting
          another scan for the same account until this one finishes.
        </p>
        {runProgress &&
        (runProgress.rules_total != null ||
          runProgress.phase != null ||
          runProgress.message != null) ? (
          <details className="mt-2 rounded-md border border-aws-orange/25 bg-black/10 dark:bg-black/25">
            <summary className="cursor-pointer text-xs text-aws-orange px-2 py-2 select-none">
              {runProgress.rules_total != null &&
              runProgress.rules_total > 0 ? (
                <>
                  Rule evaluation:{" "}
                  {Math.min(
                    100,
                    Math.round(
                      ((runProgress.rules_evaluated ?? 0) /
                        runProgress.rules_total) *
                        100,
                    ),
                  )}
                  %
                  <span className="dash-text-subtle font-normal ml-1">
                    ({runProgress.rules_evaluated ?? 0}/
                    {runProgress.rules_total} checks)
                  </span>
                </>
              ) : (
                <>Scan progress</>
              )}
            </summary>
            <div className="px-2 pb-2 pt-0 text-xs dash-text-muted space-y-2">
              {runProgress.phase ? (
                <p className="font-mono capitalize">
                  {phaseLabel(runProgress.phase)}
                </p>
              ) : null}
              {runProgress.message ? (
                <p className="dash-text-subtle">{runProgress.message}</p>
              ) : null}
              {runProgress.rules_total != null &&
              runProgress.rules_total > 0 ? (
                <div className="h-1.5 w-full rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                  <div
                    className="h-full bg-aws-orange transition-[width] duration-300 ease-out"
                    style={{
                      width: `${Math.min(
                        100,
                        Math.round(
                          ((runProgress.rules_evaluated ?? 0) /
                            runProgress.rules_total) *
                            100,
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
    </output>
  );
}
