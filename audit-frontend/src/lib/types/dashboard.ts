export type Account = {
  id: string;
  account_id: string;
  role_arn: string;
  status: string;
  last_verify_error_code?: string | null;
};

export type ScanHistoryRow = {
  id: string;
  platform_account_id: string;
  aws_account_id: string;
  created_at?: string | null;
  status: string;
  rule_pack_version: string;
  error_code: string | null;
  started_at: string | null;
  finished_at: string | null;
  error_summary?: string | null;
  optimistic?: boolean;
};

export type FindingRow = {
  id: string;
  check_id: string;
  pillar: string;
  severity: string;
  status: string;
  remediation_hint?: string | null;
  evidence_json?: Record<string, unknown> | unknown[] | null;
};

export type RunProgress = {
  phase?: string;
  rules_evaluated?: number;
  rules_total?: number;
  message?: string;
};

export type RunSummary = {
  total?: number;
  by_severity?: Record<string, number>;
  by_pillar?: Record<string, number>;
  by_status?: Record<string, number>;
  groups?: Record<string, Record<string, number>>;
  failed_groups?: Record<string, Record<string, number>>;
  progress?: RunProgress;
};

export type RunDetailState = {
  status: string;
  summary_json: RunSummary | null;
  started_at: string | null;
  finished_at: string | null;
  error_summary: string | null;
  error_code: string | null;
};

export type PrecheckEntry = {
  id?: string;
  label?: string;
  aws_error_code?: string;
  detail?: string;
  iam_actions?: string[];
  hint?: string;
  resource?: string;
};

export type GroupPageState = {
  items: FindingRow[];
  total: number;
  skip: number;
  loaded: boolean;
};

export type StructuredGroup = {
  pillar: string;
  severity: string;
  count: number;
};
