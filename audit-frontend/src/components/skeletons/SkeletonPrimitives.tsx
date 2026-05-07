import type { ReactNode } from "react";

export function SkeletonBar({
  className = "",
}: Readonly<{ className?: string }>) {
  return (
    <div
      className={`animate-pulse rounded-md bg-[var(--panel)]/70 shadow-[inset_0_0_0_1px_var(--border)] ${className}`}
      aria-hidden
    />
  );
}

export function SkeletonBreadcrumbRow() {
  return (
    <div className="flex flex-wrap items-center gap-2" aria-hidden>
      <SkeletonBar className="h-3.5 w-16" />
      <span className="text-[var(--dash-text-subtle)] opacity-40">/</span>
      <SkeletonBar className="h-3.5 w-36" />
    </div>
  );
}

export function SkeletonPanel({
  children,
  className = "",
}: Readonly<{
  children: ReactNode;
  className?: string;
}>) {
  return (
    <section
      className={`rounded-lg border border-[var(--border)] bg-[var(--dash-surface-card)] p-4 sm:p-5 ${className}`}
    >
      {children}
    </section>
  );
}

export function SkeletonTableBlock({
  titleWidthClass = "w-48",
  rows = 5,
  columns = 4,
}: Readonly<{
  titleWidthClass?: string;
  rows?: number;
  columns?: number;
}>) {
  return (
    <SkeletonPanel className="space-y-4">
      <div className="space-y-2">
        <SkeletonBar className={`h-6 ${titleWidthClass}`} />
        <SkeletonBar className="h-3 w-full max-w-2xl opacity-70" />
      </div>
      <div className="space-y-2 pt-1">
        <div
          className="grid gap-2 border-b border-[var(--border)] pb-2"
          style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }}
        >
          {Array.from({ length: columns }).map((_, i) => (
            <SkeletonBar key={`h-${i}`} className="h-3 w-3/4 max-w-[6rem]" />
          ))}
        </div>
        {Array.from({ length: rows }).map((_, r) => (
          <div
            key={`r-${r}`}
            className="grid gap-2 py-2 border-b border-[var(--border)]/60 last:border-0"
            style={{
              gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))`,
            }}
          >
            {Array.from({ length: columns }).map((_, c) => (
              <SkeletonBar
                key={`c-${r}-${c}`}
                className={`h-4 ${c === 0 ? "w-full" : "w-4/5"}`}
              />
            ))}
          </div>
        ))}
      </div>
    </SkeletonPanel>
  );
}
