"use client";

import Alert from "@cloudscape-design/components/alert";

export function DashboardErrorBanner({
  message,
}: {
  readonly message: string;
}) {
  return (
    <Alert type="error" statusIconAriaLabel="Error">
      <span className="whitespace-pre-wrap">{message}</span>
    </Alert>
  );
}
