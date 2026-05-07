"use client";

export type DashboardFindingsFilterPanelProps = {
  readonly failedOnly: boolean;
  readonly onToggle: () => void;
};

export function DashboardFindingsFilterPanel({
  failedOnly,
  onToggle,
}: DashboardFindingsFilterPanelProps) {
  return (
    <div className="flex flex-wrap items-center gap-3 rounded-xl border border-[var(--border)] bg-[var(--panel)]/50 px-4 py-3">
      <span className="text-xs dash-text-subtle uppercase tracking-wide">
        Findings filter
      </span>
      <button
        type="button"
        role="switch"
        aria-checked={!failedOnly}
        onClick={onToggle}
        className={`relative inline-flex h-7 w-12 shrink-0 rounded-full transition-colors ${
          failedOnly
            ? "bg-slate-400 dark:bg-slate-700"
            : "bg-emerald-600 dark:bg-emerald-700"
        }`}
      >
        <span
          className={`absolute top-0.5 left-0.5 h-6 w-6 rounded-full bg-white shadow transition-transform ${
            failedOnly ? "translate-x-0" : "translate-x-5"
          }`}
        />
      </button>
      <span className="text-sm dash-text-secondary">
        {failedOnly
          ? "Failed checks only (default)"
          : "All statuses (passed & unknown included)"}
      </span>
    </div>
  );
}
