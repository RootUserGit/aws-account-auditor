"use client";

const SIZE_CLASS = {
  xs: "h-3.5 w-3.5",
  sm: "h-4 w-4",
  md: "h-5 w-5",
} as const;

export type InlineLoaderProps = Readonly<{
  /** Visible text; pass `""` for spinner-only (aria-label still set). */
  label?: string;
  size?: keyof typeof SIZE_CLASS;
  className?: string;
}>;

/** Compact spinner for tables and sections. */
export function InlineLoader({
  label = "Loading…",
  size = "sm",
  className = "",
}: InlineLoaderProps) {
  const dim = SIZE_CLASS[size];
  const showText = label !== "";
  const aria = showText ? label : "Loading";

  return (
    <span
      className={`inline-flex items-center justify-center gap-2 dash-text-muted ${className}`.trim()}
      role="status"
      aria-live="polite"
      aria-busy="true"
      aria-label={aria}
    >
      <svg
        className={`animate-spin ${dim} shrink-0 text-[var(--accent)] opacity-90`}
        xmlns="http://www.w3.org/2000/svg"
        fill="none"
        viewBox="0 0 24 24"
        aria-hidden
      >
        <circle
          className="opacity-20"
          cx="12"
          cy="12"
          r="10"
          stroke="currentColor"
          strokeWidth="4"
        />
        <path
          className="opacity-80"
          fill="currentColor"
          d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
        />
      </svg>
      {showText ? <span className="text-xs">{label}</span> : null}
    </span>
  );
}
