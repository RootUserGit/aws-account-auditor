"use client";

import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import SpaceBetween from "@cloudscape-design/components/space-between";
import type { PrecheckEntry } from "@/lib/types/dashboard";

export type DashboardPrecheckBannerProps = {
  readonly entries: PrecheckEntry[];
  readonly onDismiss: () => void;
};

export function DashboardPrecheckBanner({
  entries,
  onDismiss,
}: DashboardPrecheckBannerProps) {
  return (
    <Box
      padding={{ horizontal: "l", vertical: "l" }}
      variant="div"
      className="rounded-xl border border-amber-700/40 bg-amber-950/20 dark:bg-amber-950/25"
    >
      <SpaceBetween size="s" direction="vertical">
        <div>
          <p className="text-sm font-semibold text-amber-900 dark:text-amber-100">
            Permission precheck: some optional collectors may be limited
          </p>
          <p className="text-xs dash-text-muted leading-relaxed mt-2">
            Required IAM actions passed; the scan was enqueued. Review gaps
            below and extend{" "}
            <code className="dash-text-code font-mono text-[11px]">
              policies/auditor-policy.json
            </code>{" "}
            on the customer role for fuller coverage.
          </p>
          <ul className="text-xs dash-text-secondary list-disc pl-5 space-y-1 mt-2">
            {entries.map((w, i) => (
              <li key={`${w.id ?? "row"}-${i}`}>
                <span className="font-medium dash-text-primary">
                  {w.label ?? w.id ?? "Check"}
                </span>
                {w.aws_error_code ? (
                  <span className="dash-text-subtle">
                    {" "}
                    — {w.aws_error_code}
                  </span>
                ) : null}
                {w.detail ? (
                  <span className="block dash-text-muted mt-0.5">
                    {w.detail}
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
        <Button variant="link" onClick={onDismiss}>
          Dismiss
        </Button>
      </SpaceBetween>
    </Box>
  );
}
