"use client";

import Link from "next/link";
import {
  FINDINGS_PAGE_SIZE,
  PILLAR_LABELS,
  PILLAR_ORDER,
} from "@/lib/constants/dashboard";

const PILLAR_ORDER_SET = new Set<string>(PILLAR_ORDER);

function isOrderedPillar(pillar: string): boolean {
  return PILLAR_ORDER_SET.has(pillar);
}
import {
  colorForCheckStatus,
  colorForSeverity,
} from "@/lib/utils/dashboard-chart";
import { groupKey } from "@/lib/utils/dashboard-group";
import { playbookFromEvidence } from "@/lib/utils/dashboard-normalize";
import type {
  FindingRow,
  RunDetailState,
  StructuredGroup,
} from "@/lib/types/dashboard";

export type DashboardGroupedFindingsProps = {
  readonly runId: string;
  readonly run: RunDetailState | null;
  readonly terminal: boolean;
  readonly mergedGroups: Record<string, Record<string, number>> | undefined;
  readonly failedOnly: boolean;
  readonly structuredGroups: StructuredGroup[];
  readonly pages: Record<
    string,
    { items: FindingRow[]; total: number; skip: number; loaded: boolean }
  >;
  readonly onGroupToggle: (
    open: boolean,
    pillar: string,
    severity: string,
  ) => void;
  readonly onFetchGroupPage: (
    pillar: string,
    severity: string,
    skip: number,
  ) => void;
};

function playbookStepKey(checkId: string, step: string, index: number) {
  const head = step.slice(0, 64);
  return `${checkId}-${index}-${head}`;
}

export function DashboardGroupedFindings({
  runId,
  run,
  terminal,
  mergedGroups,
  failedOnly,
  structuredGroups,
  pages,
  onGroupToggle,
  onFetchGroupPage,
}: DashboardGroupedFindingsProps) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap justify-between items-center gap-2">
        <h3 className="text-sm font-medium dash-text-secondary uppercase tracking-wider">
          Grouped findings
        </h3>
        {!mergedGroups && terminal && run?.status === "succeeded" ? (
          <span className="text-[10px] dash-text-muted">
            Re-run audits to store group metadata on the server; showing derived
            groups from a capped sample.
          </span>
        ) : null}
      </div>

      {structuredGroups.length === 0 && terminal ? (
        <p className="text-sm dash-text-muted border border-dashed border-[var(--border)] rounded-xl p-6 text-center">
          No grouped counts available yet. Re-run audits to store group metadata
          on the server, or wait for summary data.
        </p>
      ) : null}

      <div className="space-y-2">
        {PILLAR_ORDER.filter((p) =>
          structuredGroups.some((g) => g.pillar === p),
        ).map((pillar) => (
          <details
            key={pillar}
            className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/50 overflow-hidden group/pillar"
          >
            <summary className="cursor-pointer px-4 py-3 text-sm font-medium dash-text-primary hover:bg-[var(--panel-hover)] flex items-center justify-between gap-2 list-none [&::-webkit-details-marker]:hidden">
              <span className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-aws-orange shrink-0" />
                {PILLAR_LABELS[pillar] ?? pillar}
              </span>
              <span className="text-xs dash-text-muted">
                {structuredGroups
                  .filter((g) => g.pillar === pillar)
                  .reduce((a, g) => a + g.count, 0)}{" "}
                checks
              </span>
            </summary>
            <div className="border-t border-[var(--border)] px-2 pb-3 space-y-1">
              {structuredGroups
                .filter((g) => g.pillar === pillar)
                .map(({ severity, count }) => {
                  const key = groupKey(pillar, severity);
                  const pageState = pages[key];
                  const pagesCount = pageState
                    ? Math.ceil(pageState.total / FINDINGS_PAGE_SIZE)
                    : 1;
                  return (
                    <details
                      key={key}
                      className="rounded-lg border border-[var(--border)]/60 dash-surface-nested overflow-hidden"
                      onToggle={(e) => {
                        const el = e.currentTarget;
                        onGroupToggle(el.open, pillar, severity);
                      }}
                    >
                      <summary className="cursor-pointer px-3 py-2.5 flex flex-wrap items-center justify-between gap-2 hover:bg-black/[0.03] dark:hover:bg-white/[0.03] list-none [&::-webkit-details-marker]:hidden">
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
                          <span className="text-sm dash-text-secondary">
                            {count} {failedOnly ? "failed" : "total"}
                          </span>
                        </span>
                        <span className="text-[10px] dash-text-subtle">
                          Click to load · paginated
                        </span>
                      </summary>
                      <div className="border-t border-[var(--border)]/60 px-2 py-3 space-y-2">
                        {pageState?.loaded ? null : (
                          <p className="text-xs dash-text-muted px-2">
                            Loading…
                          </p>
                        )}
                        {pageState?.loaded && pageState.items.length === 0 ? (
                          <p className="text-xs dash-text-muted px-2">
                            No rows in this slice.
                          </p>
                        ) : null}
                        {pageState?.loaded
                          ? pageState.items.map((f) => {
                              const pb = playbookFromEvidence(f.evidence_json);
                              return (
                                <details
                                  key={f.id}
                                  className="rounded-lg bg-[var(--panel)]/80 border border-[var(--border)]/50 overflow-hidden"
                                >
                                  <summary className="cursor-pointer px-3 py-2 flex flex-wrap items-center gap-2 text-left hover:bg-[var(--panel-hover)] list-none [&::-webkit-details-marker]:hidden">
                                    <span className="font-mono text-xs text-aws-orange shrink-0">
                                      {f.check_id}
                                    </span>
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
                                  <div className="border-t border-[var(--border)]/40 px-3 py-3 space-y-3 text-sm dash-text-secondary">
                                    {f.remediation_hint ? (
                                      <div>
                                        <div className="text-[10px] uppercase tracking-wider dash-text-muted mb-1">
                                          Summary
                                        </div>
                                        <p className="leading-relaxed">
                                          {f.remediation_hint}
                                        </p>
                                      </div>
                                    ) : null}
                                    {pb.length > 0 ? (
                                      <div>
                                        <div className="text-[10px] uppercase tracking-wider dash-text-muted mb-2">
                                          Production remediation playbook
                                        </div>
                                        <ol className="list-decimal list-inside space-y-2 text-xs leading-relaxed dash-text-muted">
                                          {pb.map((step, i) => (
                                            <li
                                              key={playbookStepKey(
                                                f.check_id,
                                                step,
                                                i,
                                              )}
                                            >
                                              {step}
                                            </li>
                                          ))}
                                        </ol>
                                      </div>
                                    ) : null}
                                    <Link
                                      href={`/dashboard/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(f.id)}`}
                                      className="inline-flex items-center gap-1 text-xs font-medium dash-link hover:underline"
                                    >
                                      Open full evidence view →
                                    </Link>
                                  </div>
                                </details>
                              );
                            })
                          : null}
                        {pageState &&
                        pageState.loaded &&
                        pageState.total > FINDINGS_PAGE_SIZE ? (
                          <div className="flex flex-wrap items-center justify-between gap-2 px-2 pt-2">
                            <span className="text-[10px] dash-text-muted">
                              Page{" "}
                              {Math.floor(pageState.skip / FINDINGS_PAGE_SIZE) +
                                1}{" "}
                              / {pagesCount} · {pageState.total} total
                            </span>
                            <div className="flex gap-2">
                              <button
                                type="button"
                                disabled={pageState.skip <= 0}
                                onClick={() =>
                                  onFetchGroupPage(
                                    pillar,
                                    severity,
                                    Math.max(
                                      0,
                                      pageState.skip - FINDINGS_PAGE_SIZE,
                                    ),
                                  )
                                }
                                className="text-xs rounded-md border border-[var(--border)] px-2 py-1 disabled:opacity-40 hover:bg-[var(--panel-hover)]"
                              >
                                Previous
                              </button>
                              <button
                                type="button"
                                disabled={
                                  pageState.skip + FINDINGS_PAGE_SIZE >=
                                  pageState.total
                                }
                                onClick={() =>
                                  onFetchGroupPage(
                                    pillar,
                                    severity,
                                    pageState.skip + FINDINGS_PAGE_SIZE,
                                  )
                                }
                                className="text-xs rounded-md border border-[var(--border)] px-2 py-1 disabled:opacity-40 hover:bg-[var(--panel-hover)]"
                              >
                                Next
                              </button>
                            </div>
                          </div>
                        ) : null}
                      </div>
                    </details>
                  );
                })}
            </div>
          </details>
        ))}

        {structuredGroups.some((g) => !isOrderedPillar(g.pillar)) ? (
          <details className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/50">
            <summary className="cursor-pointer px-4 py-3 text-sm dash-text-secondary hover:bg-[var(--panel-hover)] list-none [&::-webkit-details-marker]:hidden">
              Other pillars
            </summary>
            <div className="border-t border-[var(--border)] px-2 py-2 text-xs dash-text-muted">
              {structuredGroups
                .filter((g) => !isOrderedPillar(g.pillar))
                .map((g) => `${g.pillar}/${g.severity}: ${g.count}`)
                .join(" · ")}
            </div>
          </details>
        ) : null}
      </div>
    </div>
  );
}
