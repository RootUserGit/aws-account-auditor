import type {
  FindingRow,
  RunDetailState,
  RunSummary,
  ScanHistoryRow,
} from "@/lib/types/dashboard";

export function normalizeScanHistoryRow(raw: unknown): ScanHistoryRow | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  const id = typeof o.id === "string" ? o.id : "";
  if (!id) return null;
  const pid = o.platform_account_id;
  const platform_account_id =
    typeof pid === "string" ? pid : typeof pid === "number" ? String(pid) : "";
  return {
    id,
    platform_account_id,
    aws_account_id:
      typeof o.aws_account_id === "string" ? o.aws_account_id : "",
    created_at: typeof o.created_at === "string" ? o.created_at : null,
    status: typeof o.status === "string" ? o.status : "",
    rule_pack_version:
      typeof o.rule_pack_version === "string" ? o.rule_pack_version : "v1",
    error_code:
      o.error_code === null || typeof o.error_code === "string"
        ? o.error_code
        : null,
    started_at:
      o.started_at === null || typeof o.started_at === "string"
        ? o.started_at
        : null,
    finished_at:
      o.finished_at === null || typeof o.finished_at === "string"
        ? o.finished_at
        : null,
    error_summary:
      o.error_summary === null || typeof o.error_summary === "string"
        ? o.error_summary
        : null,
  };
}

export function normalizeRunDetail(
  raw: Record<string, unknown> | null,
): RunDetailState | null {
  if (!raw || typeof raw !== "object") return null;
  return {
    status:
      typeof raw.status === "string" ? raw.status : String(raw.status ?? ""),
    summary_json: (raw.summary_json as RunSummary | null) ?? null,
    started_at: typeof raw.started_at === "string" ? raw.started_at : null,
    finished_at: typeof raw.finished_at === "string" ? raw.finished_at : null,
    error_summary:
      raw.error_summary === null || typeof raw.error_summary === "string"
        ? raw.error_summary
        : null,
    error_code:
      raw.error_code === null || typeof raw.error_code === "string"
        ? raw.error_code
        : null,
  };
}

export function playbookFromEvidence(
  ev: FindingRow["evidence_json"],
): string[] {
  if (!ev || typeof ev !== "object" || Array.isArray(ev)) return [];
  const pb = (ev as Record<string, unknown>).remediation_playbook;
  return Array.isArray(pb)
    ? pb.filter((x): x is string => typeof x === "string")
    : [];
}
