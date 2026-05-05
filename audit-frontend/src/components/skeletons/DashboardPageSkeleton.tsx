import {
  SkeletonBar,
  SkeletonBreadcrumbRow,
  SkeletonPanel,
  SkeletonTableBlock,
} from "./SkeletonPrimitives";

export function DashboardPageSkeleton() {
  return (
    <div
      className="dashboard-tailwind-surface bg-[var(--dash-surface-wrap)] w-full max-w-[1440px] mx-auto space-y-8"
      aria-label="Loading dashboard"
    >
      <SkeletonBreadcrumbRow />

      <div className="space-y-3">
        <SkeletonBar className="h-10 w-full max-w-lg" />
        <SkeletonBar className="h-3.5 w-full max-w-4xl" />
        <SkeletonBar className="h-3.5 w-full max-w-3xl opacity-75" />
        <SkeletonBar className="h-3.5 w-full max-w-2xl opacity-60" />
      </div>

      <SkeletonTableBlock titleWidthClass="w-56" rows={4} columns={4} />

      <SkeletonTableBlock titleWidthClass="w-44" rows={5} columns={6} />

      <SkeletonPanel className="space-y-4 opacity-90">
        <SkeletonBar className="h-6 w-64" />
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <SkeletonBar key={i} className="h-24 rounded-lg" />
          ))}
        </div>
        <SkeletonBar className="h-40 w-full rounded-lg opacity-80" />
      </SkeletonPanel>
    </div>
  );
}
