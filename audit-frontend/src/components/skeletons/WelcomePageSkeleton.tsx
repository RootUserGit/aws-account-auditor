import {
  SkeletonBar,
  SkeletonBreadcrumbRow,
  SkeletonPanel,
} from "./SkeletonPrimitives";

export function WelcomePageSkeleton() {
  return (
    <div
      className="w-full max-w-[1200px] mx-auto space-y-8"
      aria-label="Loading page"
    >
      <SkeletonBreadcrumbRow />

      <div className="space-y-3">
        <SkeletonBar className="h-9 w-full max-w-xl" />
        <SkeletonBar className="h-4 w-full max-w-2xl opacity-80" />
      </div>

      <div className="flex flex-wrap gap-3">
        <SkeletonBar className="h-9 w-40 rounded" />
        <SkeletonBar className="h-9 w-44 rounded" />
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <SkeletonPanel key={i} className="space-y-3 min-h-[140px]">
            <SkeletonBar className="h-5 w-2/3" />
            <SkeletonBar className="h-3 w-full" />
            <SkeletonBar className="h-3 w-full opacity-80" />
            <SkeletonBar className="h-3 w-4/5 opacity-70" />
            <SkeletonBar className="h-10 w-10 rounded opacity-30 mt-2" />
          </SkeletonPanel>
        ))}
      </div>

      <SkeletonPanel className="space-y-3">
        <SkeletonBar className="h-5 w-40" />
        <SkeletonBar className="h-3 w-full" />
        <SkeletonBar className="h-3 w-full max-w-3xl opacity-80" />
      </SkeletonPanel>
    </div>
  );
}
