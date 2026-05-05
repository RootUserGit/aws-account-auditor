"use client";

import Button from "@cloudscape-design/components/button";
import { InlineLoader } from "@/components/InlineLoader";
import { apiEndpoints } from "@/lib/api/api-endpoints";
import {
  runStatusClassName,
  runStatusLabel,
} from "@/lib/utils/dashboard-run-labels";
import { formatDurationMs, parseIsoMs } from "@/lib/utils/dashboard-time";
import type { RunDetailState } from "@/lib/types/dashboard";

export type DashboardActiveRunHeaderProps = {
  readonly runId: string;
  readonly run: RunDetailState | null;
  readonly terminal: boolean;
  readonly scanClockMs: number;
  readonly refetchBusy: boolean;
  readonly detailLoading?: boolean;
  readonly onRefresh: () => void;
  readonly onCancelRun: () => void;
  readonly onClosePanel: () => void;
};

export function DashboardActiveRunHeader({
  runId,
  run,
  terminal,
  scanClockMs,
  refetchBusy,
  detailLoading = false,
  onRefresh,
  onCancelRun,
  onClosePanel,
}: DashboardActiveRunHeaderProps) {
  const st = run?.status?.toLowerCase() ?? "";
  const running = !terminal && st === "running" && run?.started_at;
  const queued = !terminal && st === "queued";

  return (
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h2 className="text-lg font-semibold dash-text-primary">Active run</h2>
        <p className="text-xs font-mono dash-text-muted mt-1 break-all">
          {runId}
        </p>
        <p className="text-sm dash-text-secondary mt-2 flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="shrink-0">Status:</span>
          {detailLoading ? (
            <InlineLoader label="Fetching run details…" size="xs" />
          ) : (
            <>
              <span className={runStatusClassName(run?.status ?? "")}>
                {runStatusLabel(run?.status ?? "…")}
              </span>
              {terminal ? (
                <span className="dash-text-subtle">· polling paused</span>
              ) : (
                <span className="text-aws-orange">· live updates</span>
              )}
            </>
          )}
        </p>
        {queued ? (
          <p className="text-xs text-amber-800 dark:text-amber-200/85 mt-2 leading-relaxed max-w-xl">
            This run is{" "}
            <strong className="font-medium text-amber-900 dark:text-amber-100/90">
              queued:
            </strong>{" "}
            it is in the job queue until an audit worker begins processing. If
            it stays here, verify worker processes are running and inspect their
            logs (connectivity, Redis, or errors before status updates).
          </p>
        ) : null}
        {running && run.started_at ? (
          <p className="text-xs dash-text-muted mt-2 font-mono tabular-nums">
            Elapsed{" "}
            <span className="text-aws-orange">
              {formatDurationMs(
                scanClockMs - (parseIsoMs(run.started_at) ?? 0),
              )}
            </span>
          </p>
        ) : null}
      </div>
      <div className="flex flex-wrap gap-2 items-center">
        {run?.status === "succeeded" ? (
          <Button
            variant="primary"
            href={apiEndpoints.reportHtml(runId)}
            target="_blank"
            external
          >
            HTML report
          </Button>
        ) : null}
        <Button disabled={refetchBusy} onClick={onRefresh}>
          {refetchBusy ? "Refreshing…" : "Refresh"}
        </Button>
        {terminal || detailLoading ? null : (
          <button
            type="button"
            onClick={onCancelRun}
            className="text-sm rounded-lg border border-red-200 dark:border-red-900/50 px-3 py-2 text-red-600 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-950/40"
          >
            Cancel scan
          </button>
        )}
        <button
          type="button"
          title="Hide this panel only — does not stop an in-flight audit (use Cancel scan)."
          onClick={onClosePanel}
          className="text-sm rounded-lg border border-[var(--border)] px-3 py-2 hover:bg-[var(--panel-hover)] dash-text-secondary"
        >
          Close panel
        </button>
      </div>
    </div>
  );
}
