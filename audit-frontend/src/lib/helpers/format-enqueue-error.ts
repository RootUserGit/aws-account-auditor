import type { PrecheckEntry } from "@/lib/types/dashboard";

export function formatEnqueueError(data: unknown): string {
  if (!data || typeof data !== "object") return "Run failed";
  const detail = (data as { detail?: unknown }).detail;
  if (typeof detail === "string") return detail;
  if (detail && typeof detail === "object") {
    const d = detail as {
      message?: unknown;
      code?: unknown;
      blocking?: unknown;
    };
    if (Array.isArray(d.blocking) && d.blocking.length > 0) {
      const head: string[] = [];
      const msg = String(
        d.message ??
          "Permission precheck failed — AWS denied a required read operation for this audit.",
      );
      head.push(msg);
      if (d.code != null && String(d.code).length > 0) {
        head.push(`Reference code: ${String(d.code)}`);
      }
      const lines = [...head, ""];
      for (const b of d.blocking) {
        if (b && typeof b === "object") {
          const row = b as PrecheckEntry;
          const title = row.label ?? row.id ?? "Check";
          const code = row.aws_error_code ? ` — ${row.aws_error_code}` : "";
          lines.push(`• ${title}${code}`);
          if (row.resource) lines.push(`  Resource: ${row.resource}`);
          if (row.detail)
            lines.push(`  ${String(row.detail).replace(/\n/g, "\n  ")}`);
          if (row.iam_actions && row.iam_actions.length > 0) {
            lines.push(`  IAM actions to allow: ${row.iam_actions.join(", ")}`);
          }
          if (row.hint) lines.push(`  ${row.hint}`);
          lines.push("");
        }
      }
      return lines.join("\n").trimEnd();
    }
    if ("message" in detail) {
      return String((detail as { message: unknown }).message);
    }
  }
  return "Run failed";
}
