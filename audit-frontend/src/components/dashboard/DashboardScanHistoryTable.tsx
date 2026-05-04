"use client";

import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import Container from "@cloudscape-design/components/container";
import Header from "@cloudscape-design/components/header";
import Pagination from "@cloudscape-design/components/pagination";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Table from "@cloudscape-design/components/table";
import { apiEndpoints } from "@/lib/api/api-endpoints";
import { HISTORY_PAGE_SIZE } from "@/lib/constants/dashboard";
import type { ScanHistoryRow } from "@/lib/types/dashboard";
import {
  runStatusClassName,
  runStatusLabel,
} from "@/lib/utils/dashboard-run-labels";
import {
  fmtAuditInstant,
  formatDurationMs,
  parseIsoMs,
} from "@/lib/utils/dashboard-time";
import { TimeZonePicker } from "@/components/TimeZonePicker";
import { ButtonDropdownProps } from "@cloudscape-design/components";
import { RowActionsDropdown } from "../RowActionsDropdown";

function ScanRowActions({
  row,
  scanClockMs,
  onCancelScan,
  onOpenRun,
}: Readonly<{
  row: ScanHistoryRow;
  scanClockMs: number;
  onCancelScan: (id: string) => void;
  onOpenRun: (id: string) => void;
}>) {
  const stLower = row.status?.toLowerCase() ?? "";
  const isOptimistic = row.optimistic === true;
  const isQueued = stLower === "queued";
  const isRunning = stLower === "running";
  const thisRowInFlight = isQueued || isRunning;
  const startMs = parseIsoMs(row.started_at);
  const succeeded = stLower === "succeeded";

  if (isOptimistic && isQueued) {
    return (
      <SpaceBetween direction="vertical" size="xxs">
        <Box fontSize="body-s" color="text-body-secondary">
          Hang tight — creating run…
        </Box>
      </SpaceBetween>
    );
  }
  if (isQueued) {
    return (
      <SpaceBetween direction="vertical" size="xs">
        <Box fontSize="body-s" color="text-status-warning">
          In queue — execution has not started yet.
        </Box>
        <Button variant="link" onClick={() => onCancelScan(row.id)}>
          Cancel job
        </Button>
      </SpaceBetween>
    );
  }
  if (thisRowInFlight) {
    return (
      <SpaceBetween direction="vertical" size="xs">
        <Box fontSize="body-s" color="text-status-info">
          Scan in progress ·{" "}
          {startMs != null ? formatDurationMs(scanClockMs - startMs) : "—"}
        </Box>
        <Button variant="link" onClick={() => onCancelScan(row.id)}>
          Stop scan
        </Button>
      </SpaceBetween>
    );
  }
  return (
    <div className="flex items-center justify-start">
      <RowActionsDropdown
        items={[
          {
            id: "view",
            text: "View results",
            iconName: "search",
          } satisfies ButtonDropdownProps.Item,

          ...(succeeded
            ? [
                {
                  id: "report",
                  text: "HTML report",
                  iconName: "external",
                } satisfies ButtonDropdownProps.Item,
              ]
            : []),
        ]}
        onClick={(id) => {
          if (id === "view") onOpenRun(row.id);
          if (id === "report")
            window.open(apiEndpoints.reportHtml(row.id), "_blank");
        }}
      />
    </div>
  );
}

export type DashboardScanHistoryTableProps = {
  scanHistory: ScanHistoryRow[];
  runId: string;
  scanClockMs: number;
  displayTz: string;
  onDisplayTzChange: (tz: string) => void;
  onRefresh: () => void;
  historyPage: number;
  historyTotal: number;
  onHistoryPageChange: (pageIndex: number) => void;
  onCancelScan: (id: string) => void;
  onOpenRun: (id: string) => void;
};

export function DashboardScanHistoryTable({
  scanHistory,
  runId,
  scanClockMs,
  displayTz,
  onDisplayTzChange,
  onRefresh,
  historyPage,
  historyTotal,
  onHistoryPageChange,
  onCancelScan,
  onOpenRun,
}: Readonly<DashboardScanHistoryTableProps>) {
  const pagesCount = Math.max(
    1,
    Math.ceil(historyTotal / HISTORY_PAGE_SIZE) || 1,
  );

  return (
    <Container
      header={
        <Header
          variant="h2"
          description="Recent audit runs across all onboarded accounts. Times use your selected display time zone (API stores UTC)."
          actions={
            <SpaceBetween direction="horizontal" size="s" alignItems="center">
              <Box fontSize="body-s" color="text-body-secondary">
                Time zone
              </Box>
              <TimeZonePicker value={displayTz} onChange={onDisplayTzChange} />
              <Button variant="link" onClick={onRefresh}>
                Refresh list
              </Button>
            </SpaceBetween>
          }
        >
          Scan history
        </Header>
      }
    >
      <SpaceBetween size="m" direction="vertical">
        <Table
          trackBy="id"
          variant="embedded"
          empty={
            <Box textAlign="center" color="text-body-secondary" padding="l">
              No runs on this page — start an audit from a connected account or
              change page.
            </Box>
          }
          columnDefinitions={[
            {
              id: "aws",
              header: "AWS account",
              cell: (row) => (
                <Box variant="code" fontSize="body-s">
                  {row.aws_account_id}
                </Box>
              ),
            },
            {
              id: "status",
              header: "Status",
              cell: (row) => {
                const active = row.id === runId;
                const stLower = row.status?.toLowerCase() ?? "";
                const isOptimistic = row.optimistic === true;
                const isQueued = stLower === "queued";
                return (
                  <div
                    className={
                      active
                        ? "ring-1 ring-[var(--accent)]/50 dark:ring-orange-400/40 rounded p-1 -m-1"
                        : undefined
                    }
                  >
                    <span className={runStatusClassName(row.status)}>
                      {runStatusLabel(row.status)}
                    </span>
                    {isOptimistic && isQueued ? (
                      <Box
                        fontSize="body-s"
                        color="text-body-secondary"
                        margin={{ top: "xxs" }}
                      >
                        Confirming with server…
                      </Box>
                    ) : null}
                  </div>
                );
              },
              width: 180,
            },
            {
              id: "started",
              header: "Started",
              cell: (row) => (
                <Box fontSize="body-s" color="text-body-secondary">
                  {fmtAuditInstant(row.started_at, displayTz)}
                </Box>
              ),
              width: 180,
            },
            {
              id: "finished",
              header: "Finished",
              cell: (row) => (
                <Box fontSize="body-s" color="text-body-secondary">
                  {fmtAuditInstant(row.finished_at, displayTz)}
                </Box>
              ),
              width: 180,
            },
            {
              id: "duration",
              header: "Duration",
              cell: (row) => {
                const stLower = row.status?.toLowerCase() ?? "";
                const isQueued = stLower === "queued";
                const isRunning = stLower === "running";
                const thisRowInFlight = isQueued || isRunning;
                const startMs = parseIsoMs(row.started_at);
                const endMs = parseIsoMs(row.finished_at);
                let durationStr = "—";
                if (isRunning && startMs != null) {
                  durationStr = formatDurationMs(scanClockMs - startMs);
                } else if (
                  !thisRowInFlight &&
                  startMs != null &&
                  endMs != null
                ) {
                  durationStr = formatDurationMs(endMs - startMs);
                }
                return (
                  <Box fontSize="body-s" className="tabular-nums">
                    {durationStr}
                  </Box>
                );
              },
              width: 120,
            },
            {
              id: "actions",
              header: "Actions",
              cell: (row) => (
                <ScanRowActions
                  row={row}
                  scanClockMs={scanClockMs}
                  onCancelScan={onCancelScan}
                  onOpenRun={onOpenRun}
                />
              ),
            },
          ]}
          items={scanHistory}
        />
        <div className="flex flex-wrap justify-between items-center gap-3">
          <Box fontSize="body-s" color="text-body-secondary">
            {historyTotal === 0
              ? "0 runs"
              : `Showing ${historyPage * HISTORY_PAGE_SIZE + 1}–${Math.min(historyTotal, (historyPage + 1) * HISTORY_PAGE_SIZE)} of ${historyTotal}`}
          </Box>
          {historyTotal > HISTORY_PAGE_SIZE ? (
            <Pagination
              currentPageIndex={historyPage}
              pagesCount={pagesCount}
              onChange={({ detail }) =>
                onHistoryPageChange(detail.currentPageIndex)
              }
            />
          ) : null}
        </div>
      </SpaceBetween>
    </Container>
  );
}
