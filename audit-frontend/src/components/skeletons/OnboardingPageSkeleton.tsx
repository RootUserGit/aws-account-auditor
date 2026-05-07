import {
  SkeletonBar,
  SkeletonBreadcrumbRow,
  SkeletonPanel,
} from "./SkeletonPrimitives";

export function OnboardingPageSkeleton() {
  return (
    <div
      className="w-full max-w-[800px] mx-auto space-y-8"
      aria-label="Loading onboarding"
    >
      <SkeletonBreadcrumbRow />

      <SkeletonBar className="h-9 w-64" />

      <div className="space-y-2">
        <SkeletonBar className="h-3 w-full" />
        <SkeletonBar className="h-3 w-full max-w-xl opacity-80" />
        <SkeletonBar className="h-3 w-2/3 opacity-70" />
      </div>

      <SkeletonPanel className="space-y-6">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="space-y-2">
            <SkeletonBar className="h-3.5 w-40" />
            <SkeletonBar className="h-10 w-full rounded" />
          </div>
        ))}
        <SkeletonBar className="h-9 w-32 rounded" />
        <div className="space-y-2 pt-2 border-t border-[var(--border)]">
          <SkeletonBar className="h-3.5 w-28" />
          <SkeletonBar className="h-10 w-full rounded" />
          <div className="flex flex-wrap gap-2">
            <SkeletonBar className="h-9 w-28 rounded" />
            <SkeletonBar className="h-9 w-36 rounded" />
          </div>
        </div>
      </SkeletonPanel>
    </div>
  );
}
