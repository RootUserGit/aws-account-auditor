import { SkeletonBar, SkeletonPanel } from "./SkeletonPrimitives";

export function FindingDetailPageSkeleton() {
  return (
    <div
      className="dashboard-tailwind-surface w-full max-w-[1200px] mx-auto space-y-6"
      aria-label="Loading finding"
    >
      <div className="flex flex-wrap items-center gap-2" aria-hidden>
        <SkeletonBar className="h-3.5 w-16" />
        <span className="text-[var(--dash-text-subtle)] opacity-40">/</span>
        <SkeletonBar className="h-3.5 w-40" />
        <span className="text-[var(--dash-text-subtle)] opacity-40">/</span>
        <SkeletonBar className="h-3.5 w-48" />
      </div>

      <SkeletonBar className="h-9 w-full max-w-2xl" />

      <div className="space-y-2">
        <SkeletonBar className="h-3.5 w-full max-w-3xl" />
        <SkeletonBar className="h-3.5 w-2/3 max-w-xl opacity-80" />
      </div>

      <div className="flex flex-wrap gap-2">
        {Array.from({ length: 3 }).map((_, i) => (
          <SkeletonBar key={i} className="h-8 w-28 rounded-lg" />
        ))}
      </div>

      <SkeletonPanel className="space-y-3">
        <SkeletonBar className="h-4 w-48" />
        <SkeletonBar className="h-3 w-full" />
        <SkeletonBar className="h-3 w-full opacity-80" />
        <SkeletonBar className="h-3 w-full max-w-xl opacity-70" />
      </SkeletonPanel>

      <SkeletonPanel className="space-y-3">
        <SkeletonBar className="h-3 w-56" />
        <SkeletonBar className="h-48 w-full rounded-lg opacity-60" />
      </SkeletonPanel>

      <div className="grid gap-4 lg:grid-cols-2">
        <SkeletonPanel className="min-h-[120px] space-y-2">
          <SkeletonBar className="h-4 w-32" />
          <SkeletonBar className="h-3 w-full" />
          <SkeletonBar className="h-3 w-full" />
        </SkeletonPanel>
        <SkeletonPanel className="min-h-[120px] space-y-2">
          <SkeletonBar className="h-4 w-36" />
          <SkeletonBar className="h-3 w-full" />
          <SkeletonBar className="h-3 w-4/5" />
        </SkeletonPanel>
      </div>
    </div>
  );
}
