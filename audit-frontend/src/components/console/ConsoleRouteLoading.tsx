import { InlineLoader } from "@/components/InlineLoader";

/** Full-area route transition UI (no skeleton placeholders). */
export function ConsoleRouteLoading({
  title = "Loading…",
}: Readonly<{ title?: string }>) {
  return (
    <div
      className="dashboard-tailwind-surface flex min-h-[70vh] w-full max-w-[1440px] flex-col items-center justify-center gap-4 px-4 py-16"
      role="status"
      aria-live="polite"
      aria-label={title}
    >
      <InlineLoader label={title} size="md" />
    </div>
  );
}
