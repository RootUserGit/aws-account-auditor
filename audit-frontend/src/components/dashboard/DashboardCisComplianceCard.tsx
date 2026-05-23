"use client";

import type { CisAwsFoundationsV15Summary } from "@/lib/types/dashboard";

export type DashboardCisComplianceCardProps = {
  readonly cis: CisAwsFoundationsV15Summary | null | undefined;
};

const RING_R = 15;
const RING_C = 2 * Math.PI * RING_R; // ~94.25

function bandProgressClass(band: string | null | undefined): string {
  if (band === "green") {
    return "bg-emerald-500 dark:bg-emerald-400";
  }
  if (band === "amber") {
    return "bg-amber-500 dark:bg-amber-400";
  }
  if (band === "red") {
    return "bg-rose-600 dark:bg-rose-500";
  }
  return "bg-[var(--border)]";
}

function bandRingClass(band: string | null | undefined): string {
  if (band === "green") {
    return "stroke-emerald-500 dark:stroke-emerald-400";
  }
  if (band === "amber") {
    return "stroke-amber-500 dark:stroke-amber-400";
  }
  if (band === "red") {
    return "stroke-rose-600 dark:stroke-rose-500";
  }
  return "stroke-[var(--border)]";
}

function bandBadge(band: string | null | undefined): { label: string; className: string } {
  if (band === "green") {
    return {
      label: "Strong",
      className:
        "border-emerald-600/40 bg-emerald-500/10 text-emerald-800 dark:text-emerald-200/95",
    };
  }
  if (band === "amber") {
    return {
      label: "Needs attention",
      className:
        "border-amber-600/40 bg-amber-500/10 text-amber-950 dark:text-amber-100/90",
    };
  }
  if (band === "red") {
    return {
      label: "At risk",
      className: "border-rose-600/40 bg-rose-500/10 text-rose-900 dark:text-rose-100/95",
    };
  }
  return {
    label: "—",
    className: "border-[var(--border)] bg-[var(--panel)] dash-text-muted",
  };
}

export function DashboardCisComplianceCard({
  cis,
}: DashboardCisComplianceCardProps) {
  if (!cis) {
    return null;
  }

  const total = cis.mapped_checks_total ?? 0;
  const score = cis.score_percent;
  const failing = cis.failing_control_count ?? 0;
  const band = cis.band;
  const passed = cis.mapped_checks_passed ?? 0;
  const failedMapped = cis.mapped_checks_failed ?? 0;
  const unknownMapped = cis.mapped_checks_unknown ?? 0;

  if (total === 0 || score == null) {
    return (
      <div
        className="rounded-2xl border border-[var(--border)] bg-[var(--panel)]/60 p-5"
        role="status"
      >
        <div className="text-[10px] uppercase tracking-widest dash-text-subtle">
          CIS AWS Foundations Benchmark v1.5
        </div>
        <p className="mt-3 text-sm dash-text-secondary leading-relaxed max-w-2xl">
          No CIS-mapped checks in this run yet. Add{" "}
          <code className="font-mono text-[11px] dash-text-primary">cis_control</code>{" "}
          to rules or extend server mappings in{" "}
          <code className="font-mono text-[11px] dash-text-primary">
            cis_controls_v15.py
          </code>
          .
        </p>
      </div>
    );
  }

  const badge = bandBadge(band);
  const arcLen = (score / 100) * RING_C;
  const headlineAria = `CIS AWS Foundations Benchmark version 1.5: ${score} percent compliant. ${failing} CIS controls have at least one failing check.`;

  return (
    <section
      className="rounded-2xl border border-[var(--border)] bg-gradient-to-br from-[var(--panel)]/90 to-[var(--panel)]/40 p-5 sm:p-6 shadow-sm"
      role="region"
      aria-label={headlineAria}
    >
      <div className="flex flex-col gap-6 lg:flex-row lg:items-stretch lg:gap-8">
        <div className="flex shrink-0 items-center gap-5">
          <div className="relative h-[5.5rem] w-[5.5rem] shrink-0" aria-hidden>
            <svg
              className="h-full w-full -rotate-90"
              viewBox="0 0 36 36"
              xmlns="http://www.w3.org/2000/svg"
            >
              <circle
                cx="18"
                cy="18"
                r={RING_R}
                fill="none"
                className="stroke-[var(--border)] opacity-80"
                strokeWidth="3.2"
              />
              <circle
                cx="18"
                cy="18"
                r={RING_R}
                fill="none"
                className={`${bandRingClass(band)} transition-[stroke-dasharray] duration-500 ease-out`}
                strokeWidth="3.2"
                strokeLinecap="round"
                strokeDasharray={`${arcLen} ${Math.max(0.001, RING_C - arcLen)}`}
              />
            </svg>
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-[9px] font-medium uppercase tracking-wider dash-text-subtle">
                CIS
              </span>
              <span className="text-xl font-bold tabular-nums leading-none dash-text-primary">
                {score}
                <span className="text-sm font-semibold align-top">%</span>
              </span>
            </div>
          </div>

          <div className="min-w-0 space-y-2">
            <div className="text-[10px] uppercase tracking-widest dash-text-subtle">
              Compliance score
            </div>
            <h2 className="text-base font-semibold leading-snug dash-text-primary sm:text-lg">
              CIS AWS Foundations Benchmark v1.5
            </h2>
            <span
              className={`inline-flex w-fit items-center rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${badge.className}`}
            >
              {badge.label}
            </span>
          </div>
        </div>

        <div className="min-w-0 flex-1 space-y-4 border-t border-[var(--border)] pt-6 lg:border-l lg:border-t-0 lg:pl-8 lg:pt-0">
          <div className="space-y-2">
            <div className="flex h-2.5 overflow-hidden rounded-full bg-black/10 dark:bg-white/10">
              <div
                className={`rounded-full ${bandProgressClass(band)} transition-all duration-500 ease-out`}
                style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
              />
            </div>
            <p className="text-sm font-medium dash-text-primary">
              {failing === 0 ? (
                <>No CIS control failures in this scan.</>
              ) : (
                <>
                  <span className="tabular-nums">{failing}</span>{" "}
                  {failing === 1 ? "CIS control" : "CIS controls"} with at least
                  one failing check
                </>
              )}
            </p>
            <p className="text-xs dash-text-muted leading-relaxed">
              Score uses only checks mapped to CIS controls ({passed} passed,{" "}
              {failedMapped} failed of {total} mapped). This can differ from
              total failed rules below.
            </p>
          </div>

          <div className="flex flex-wrap gap-2">
            <span className="inline-flex items-center rounded-lg border border-[var(--border)] bg-black/5 px-2.5 py-1 text-[11px] tabular-nums dark:bg-white/5">
              <span className="dash-text-subtle mr-1.5">Mapped</span>
              {total}
            </span>
            <span className="inline-flex items-center rounded-lg border border-emerald-600/25 bg-emerald-500/10 px-2.5 py-1 text-[11px] tabular-nums text-emerald-800 dark:text-emerald-200/90">
              <span className="mr-1.5 opacity-80">Passed</span>
              {passed}
            </span>
            <span className="inline-flex items-center rounded-lg border border-rose-600/25 bg-rose-500/10 px-2.5 py-1 text-[11px] tabular-nums text-rose-900 dark:text-rose-100/90">
              <span className="mr-1.5 opacity-80">Failed</span>
              {failedMapped}
            </span>
            {unknownMapped > 0 ? (
              <span className="inline-flex items-center rounded-lg border border-amber-600/25 bg-amber-500/10 px-2.5 py-1 text-[11px] tabular-nums text-amber-950 dark:text-amber-100/90">
                <span className="mr-1.5 opacity-80">Unknown</span>
                {unknownMapped}
              </span>
            ) : null}
          </div>

          {unknownMapped > 0 ? (
            <details className="group text-xs">
              <summary className="cursor-pointer list-none dash-text-secondary underline decoration-dotted underline-offset-2 hover:dash-text-primary [&::-webkit-details-marker]:hidden">
                <span className="inline-flex items-center gap-1">
                  Why are some mapped checks “unknown”?
                  <span className="text-[10px] opacity-70 transition group-open:rotate-180">
                    ▼
                  </span>
                </span>
              </summary>
              <p className="mt-2 max-w-prose border-l-2 border-[var(--border)] pl-3 dash-text-muted leading-relaxed">
                Unknown means the rule could not decide pass or fail (missing
                permissions, empty inventory, or an outdated worker). They
                still count toward the denominator for this CIS score. See the
                note under the summary cards for how to fix evaluator issues.
              </p>
            </details>
          ) : null}
        </div>
      </div>
    </section>
  );
}
