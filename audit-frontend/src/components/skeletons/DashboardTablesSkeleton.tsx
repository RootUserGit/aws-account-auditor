import { SkeletonBar, SkeletonPanel } from "./SkeletonPrimitives";

export function DashboardAccountsCardsSkeleton() {
  return (
    <div className="w-full" aria-hidden>
      <SkeletonPanel className="space-y-4">
        <div className="space-y-2">
          <SkeletonBar className="h-5 w-48" />
          <SkeletonBar className="h-3 w-full max-w-2xl opacity-70" />
        </div>
        <div className="flex flex-wrap gap-3">
          <SkeletonBar className="h-9 w-full max-w-md" />
          <SkeletonBar className="h-9 w-full max-w-xs" />
        </div>
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {[0, 1, 2].map((i) => (
            <SkeletonBar key={i} className="h-40 w-full rounded-md" />
          ))}
        </div>
      </SkeletonPanel>
    </div>
  );
}

/** @deprecated Use DashboardAccountsCardsSkeleton */
export const DashboardAccountsTableSkeleton = DashboardAccountsCardsSkeleton;

export function DashboardScanHistoryTableSkeleton() {
  return (
    <div className="w-full" aria-hidden>
      <CompactTableSkeleton titleW="w-40" rows={4} cols={6} />
    </div>
  );
}

export function DashboardTablesSkeleton() {
  return (
    <div className="space-y-8 w-full" aria-hidden>
      <CompactTableSkeleton titleW="w-48" rows={3} cols={4} />
      <CompactTableSkeleton titleW="w-40" rows={4} cols={6} />
    </div>
  );
}

function CompactTableSkeleton({
  titleW,
  rows,
  cols,
}: Readonly<{
  titleW: string;
  rows: number;
  cols: number;
}>) {
  return (
    <SkeletonPanel className="space-y-3">
      <div className="space-y-2">
        <SkeletonBar className={`h-5 ${titleW}`} />
        <SkeletonBar className="h-3 w-full max-w-xl opacity-70" />
      </div>
      <div
        className="grid gap-2 border-b border-[var(--border)] pb-2"
        style={{ gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))` }}
      >
        {Array.from({ length: cols }).map((_, i) => (
          <SkeletonBar key={`h-${i}`} className="h-3 w-16" />
        ))}
      </div>
      {Array.from({ length: rows }).map((_, r) => (
        <div
          key={`row-${r}`}
          className="grid gap-2 py-1.5"
          style={{ gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))` }}
        >
          {Array.from({ length: cols }).map((_, c) => (
            <SkeletonBar key={`${r}-${c}`} className="h-8 w-full opacity-90" />
          ))}
        </div>
      ))}
    </SkeletonPanel>
  );
}
