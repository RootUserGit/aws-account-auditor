"use client";

import BreadcrumbGroup from "@cloudscape-design/components/breadcrumb-group";
import Box from "@cloudscape-design/components/box";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import SpaceBetween from "@cloudscape-design/components/space-between";
import { useParams, useRouter } from "next/navigation";
import { useCallback } from "react";

import { EvidenceAutoTables } from "@/components/EvidenceAutoTables";
import { InlineLoader } from "@/components/InlineLoader";
import { PaginatedTable } from "@/components/PaginatedTable";
import { useFindingDetail } from "@/hooks";
import {
  colorForCheckStatus,
  colorForSeverity,
} from "@/lib/utils/dashboard-chart";

function ageBadgeClass(days: number | null | undefined): string {
  if (days == null || Number.isNaN(days)) {
    return "bg-slate-100 text-slate-700 border border-slate-300 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-600";
  }
  if (days <= 90) {
    return "bg-emerald-100 text-emerald-900 border border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800";
  }
  if (days <= 365) {
    return "bg-amber-100 text-amber-900 border border-amber-300 dark:bg-amber-950 dark:text-amber-200 dark:border-amber-800";
  }
  return "bg-red-100 text-red-900 border border-red-300 dark:bg-red-950 dark:text-red-200 dark:border-red-800";
}

function fmtTs(v: unknown): string {
  if (v == null) return "—";
  if (typeof v === "string") return v;
  return String(v);
}

function asRecordArray(v: unknown): Record<string, unknown>[] | null {
  if (!Array.isArray(v) || v.length === 0) return null;
  if (!v.every((x) => x && typeof x === "object" && !Array.isArray(x)))
    return null;
  return v as Record<string, unknown>[];
}

/** Format ISO-ish launch times from the API / boto serialization */
function fmtLaunch(v: unknown): string {
  if (v == null || v === "") return "—";
  if (typeof v === "string") {
    const ms = Date.parse(v);
    if (!Number.isNaN(ms))
      return new Date(ms).toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      });
    return v;
  }
  return String(v);
}

function portRangeLabel(row: Record<string, unknown>): string {
  const fp = row.from_port;
  const tp = row.to_port;
  if (fp == null && tp == null) return "—";
  return `${fp ?? "?"} → ${tp ?? "?"}`;
}

function JsonBlock({ value }: Readonly<{ value: unknown }>) {
  let text: string;
  try {
    text = JSON.stringify(value, null, 2);
  } catch {
    text = String(value);
  }
  return (
    <pre className="text-xs bg-[var(--panel)] border border-[var(--border)] rounded-lg p-4 overflow-auto max-h-[32rem] dash-text-secondary font-mono">
      {text}
    </pre>
  );
}

export default function FindingDetailPage() {
  const router = useRouter();
  const params = useParams<{ runId: string; findingId: string }>();
  const runId = params.runId ?? "";
  const findingId = params.findingId ?? "";
  const { run, finding, err, loading } = useFindingDetail(runId, findingId);

  const onBreadcrumbFollow = useCallback(
    (event: CustomEvent) => {
      event.preventDefault();
      const href = (event.detail as { href?: string }).href;
      if (href && href !== "#") router.push(href);
    },
    [router],
  );

  const ev = finding?.evidence_json;
  const evObj =
    ev && typeof ev === "object" && !Array.isArray(ev)
      ? (ev as Record<string, unknown>)
      : null;

  const mfaUsers = Array.isArray(evObj?.users_without_mfa)
    ? (evObj.users_without_mfa as Record<string, unknown>[])
    : null;
  const s3Buckets = Array.isArray(evObj?.buckets_detail)
    ? (evObj.buckets_detail as Record<string, unknown>[])
    : null;
  const keyConcerns = Array.isArray(evObj?.access_key_concerns)
    ? (evObj.access_key_concerns as Record<string, unknown>[])
    : null;

  const playbook = Array.isArray(evObj?.remediation_playbook)
    ? (evObj.remediation_playbook as unknown[]).filter(
        (x): x is string => typeof x === "string",
      )
    : [];

  const sshOpenRows = asRecordArray(evObj?.open_ssh_security_groups);
  const stoppedInstRows = asRecordArray(evObj?.stopped_instances_sample);
  const eipRows = asRecordArray(evObj?.unassociated_elastic_ips);
  const volumeRows = asRecordArray(evObj?.unattached_volumes);
  const rdsBadRows = asRecordArray(evObj?.non_compliant_instances);
  const adminUserRows = asRecordArray(evObj?.users_with_administrator_access);
  const kmsRotRows = asRecordArray(evObj?.keys_without_rotation);
  const openDefSgRows = asRecordArray(evObj?.open_default_sgs);

  const dashboardHref = runId
    ? `/dashboard?run=${encodeURIComponent(runId)}`
    : "/dashboard";
  const selfHref = `/dashboard/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(findingId)}`;

  return (
    <ContentLayout
      breadcrumbs={
        <BreadcrumbGroup
          items={[
            { text: "Welcome", href: "/" },
            { text: "Operations dashboard", href: dashboardHref },
            {
              text: finding?.check_id ?? "Finding",
              href: selfHref,
            },
          ]}
          onFollow={onBreadcrumbFollow}
        />
      }
      maxContentWidth={1200}
      header={<Header variant="h1">{finding?.check_id ?? "Finding"}</Header>}
    >
      <div className="dashboard-tailwind-surface">
        <SpaceBetween size="l" direction="vertical">
          {run ? (
            <Box variant="p" color="text-body-secondary" fontSize="body-s">
              Run <Box variant="awsui-inline-code">{runId}</Box> · Account{" "}
              <Box variant="awsui-inline-code">{run.account_id}</Box> · Run
              status <span className="capitalize">{run.status}</span>
            </Box>
          ) : null}

          {err && (
            <p
              className="text-sm rounded-lg border px-3 py-3 text-red-900 bg-red-50 border-red-200 dark:text-red-300 dark:bg-red-950/30 dark:border-red-900/60"
              role="alert"
            >
              {err}
            </p>
          )}

          {loading && runId && findingId && !err ? (
            <div
              className="flex min-h-[12rem] items-center justify-center rounded-xl border border-[var(--border)] dash-surface-nested px-4 py-10"
              aria-busy="true"
            >
              <InlineLoader label="Loading finding…" />
            </div>
          ) : null}

          {finding && (
            <>
              <section
                className="flex flex-wrap items-stretch gap-2 sm:gap-3"
                aria-label="Finding metadata"
              >
                <span className="dash-meta-pill items-center">
                  <span className="dash-text-muted font-normal text-[11px] uppercase tracking-wide shrink-0">
                    Pillar
                  </span>
                  <span aria-hidden className="dash-text-subtle select-none">
                    ·
                  </span>
                  <span className="dash-text-primary capitalize">
                    {finding.pillar}
                  </span>
                </span>
                <span
                  className="dash-meta-pill dash-meta-pill--tinted items-center capitalize"
                  style={{
                    color: colorForSeverity(finding.severity),
                    borderColor: `${colorForSeverity(finding.severity)}55`,
                    background: `${colorForSeverity(finding.severity)}14`,
                  }}
                >
                  <span className="opacity-[0.85] font-normal text-[11px] uppercase tracking-wide shrink-0">
                    Severity
                  </span>
                  <span aria-hidden className="opacity-50 select-none">
                    ·
                  </span>
                  <span className="capitalize">{finding.severity}</span>
                </span>
                <span
                  className="dash-meta-pill dash-meta-pill--tinted items-center capitalize"
                  style={{
                    color: colorForCheckStatus(finding.status),
                    borderColor: `${colorForCheckStatus(finding.status)}55`,
                    background: `${colorForCheckStatus(finding.status)}14`,
                  }}
                >
                  <span className="opacity-[0.85] font-normal text-[11px] uppercase tracking-wide shrink-0">
                    Status
                  </span>
                  <span aria-hidden className="opacity-50 select-none">
                    ·
                  </span>
                  <span className="capitalize">{finding.status}</span>
                </span>
              </section>

              {finding.status === "unknown" &&
                evObj &&
                typeof evObj.error === "string" &&
                evObj.error.startsWith("unknown_evaluator:") && (
                  <section
                    className="rounded-xl border border-amber-300/90 bg-amber-50 p-5 space-y-2 dark:border-amber-700/45 dark:bg-amber-950/30"
                    role="alert"
                  >
                    <h2 className="text-xs font-medium uppercase tracking-wider text-amber-900 dark:text-amber-200/95">
                      Rule could not run on the worker
                    </h2>
                    <p className="text-sm text-amber-950 dark:text-slate-200 leading-relaxed">
                      The audit worker received this check from the rule pack,
                      but its Python process does not register an evaluator
                      named{" "}
                      <code className="font-mono text-xs text-amber-950 dark:text-amber-100/90 bg-amber-100/80 dark:bg-transparent px-1 rounded">
                        {String(evObj.error).replace(/^unknown_evaluator:/, "")}
                      </code>
                      . That almost always means the{" "}
                      <strong className="font-medium text-amber-950 dark:text-slate-100">
                        worker container or package is outdated
                      </strong>{" "}
                      — rebuild and redeploy{" "}
                      <span className="font-mono text-amber-900 dark:text-slate-300">
                        audit-worker
                      </span>{" "}
                      from the same commit as{" "}
                      <span className="font-mono text-amber-900 dark:text-slate-300">
                        audit-agents
                      </span>
                      , then run a new scan.
                    </p>
                  </section>
                )}

              {finding.remediation_hint &&
                !(
                  typeof evObj?.error === "string" &&
                  evObj.error.startsWith("unknown_evaluator:")
                ) && (
                  <section className="rounded-xl border border-orange-200 bg-orange-50/90 p-5 dark:border-aws-orange/35 dark:bg-aws-orange/5 my-4">
                    <h2 className="text-xs font-medium uppercase tracking-wider text-aws-orange mb-2">
                      Remediation summary
                    </h2>
                    <p className="text-sm dash-text-secondary leading-relaxed">
                      {finding.remediation_hint}
                    </p>
                  </section>
                )}

              {finding.remediation_hint &&
                typeof evObj?.error === "string" &&
                evObj.error.startsWith("unknown_evaluator:") && (
                  <section className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/50 p-4">
                    <p className="text-xs dash-text-muted leading-relaxed">
                      Generic remediation text is hidden for this row because
                      the check did not execute — fix the worker version first.
                    </p>
                  </section>
                )}

              {playbook.length > 0 && (
                <section className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/60 p-5 space-y-3 mb-3">
                  <h2 className="text-xs font-medium uppercase tracking-wider dash-text-muted">
                    Production remediation playbook
                  </h2>
                  <ol className="list-decimal list-inside space-y-3 text-sm dash-text-secondary leading-relaxed pl-0.5">
                    {playbook.map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ol>
                </section>
              )}

              {sshOpenRows && sshOpenRows.length > 0 && finding && (
                <PaginatedTable
                  key={`${finding.id}-ssh`}
                  title="Security groups allowing SSH from the Internet"
                  subtitle="Ingress open to 0.0.0.0/0 or ::/0 on SSH (or all traffic). Review and tighten before removing access."
                  rows={sshOpenRows}
                  columns={[
                    { header: "Region", key: "region" },
                    { header: "Group ID", key: "group_id" },
                    { header: "Group name", key: "group_name" },
                    { header: "VPC", key: "vpc_id" },
                    { header: "CIDR", key: "cidr" },
                    {
                      header: "Port range",
                      render: (row) => (
                        <span className="font-mono">{portRangeLabel(row)}</span>
                      ),
                    },
                  ]}
                />
              )}

              {stoppedInstRows && stoppedInstRows.length > 0 && finding && (
                <PaginatedTable
                  key={`${finding.id}-stopped`}
                  title="Stopped EC2 instances (sample)"
                  subtitle="Shows Name tag when present, launch time, network context — use for cleanup / rightsizing decisions."
                  rows={stoppedInstRows}
                  columns={[
                    { header: "Region", key: "region" },
                    { header: "Instance ID", key: "instance_id" },
                    { header: "Name tag", key: "name_tag" },
                    { header: "Type", key: "instance_type" },
                    {
                      header: "Launched",
                      render: (row) => fmtLaunch(row.launch_time),
                    },
                    { header: "AZ", key: "availability_zone" },
                    { header: "VPC", key: "vpc_id" },
                    { header: "Private IP", key: "private_ip" },
                    {
                      header: "Stop reason (trunc.)",
                      key: "state_transition_reason",
                    },
                  ]}
                />
              )}

              {eipRows && eipRows.length > 0 && finding && (
                <PaginatedTable
                  key={`${finding.id}-eip`}
                  title="Unassociated Elastic IPs"
                  rows={eipRows}
                  columns={[
                    { header: "Region", key: "region" },
                    { header: "Allocation ID", key: "allocation_id" },
                    { header: "Public IPv4", key: "public_ip" },
                  ]}
                />
              )}

              {volumeRows && volumeRows.length > 0 && finding && (
                <PaginatedTable
                  key={`${finding.id}-vol`}
                  title="Unattached EBS volumes (sample)"
                  rows={volumeRows}
                  columns={[
                    { header: "Region", key: "region" },
                    { header: "Volume ID", key: "volume_id" },
                    { header: "Size (GiB)", key: "size_gb" },
                    { header: "Type", key: "volume_type" },
                    { header: "Snapshot", key: "snapshot_id" },
                  ]}
                />
              )}

              {rdsBadRows && rdsBadRows.length > 0 && finding && (
                <PaginatedTable
                  key={`${finding.id}-rds`}
                  title="RDS instances — exposure / encryption"
                  subtitle="Publicly accessible or storage not encrypted in the sampled inventory."
                  rows={rdsBadRows}
                  columns={[
                    { header: "Region", key: "region" },
                    { header: "DB identifier", key: "db_instance_identifier" },
                    { header: "Engine", key: "engine" },
                    {
                      header: "Public?",
                      render: (row) => (row.publicly_accessible ? "Yes" : "No"),
                    },
                    {
                      header: "Storage encrypted?",
                      render: (row) => (row.storage_encrypted ? "Yes" : "No"),
                    },
                  ]}
                />
              )}

              {adminUserRows && adminUserRows.length > 0 && finding && (
                <PaginatedTable
                  key={`${finding.id}-adm`}
                  title="IAM users with AdministratorAccess"
                  rows={adminUserRows}
                  columns={[
                    { header: "User", key: "user_name" },
                    { header: "Policy ARN", key: "policy_arn" },
                  ]}
                />
              )}

              {kmsRotRows && kmsRotRows.length > 0 && finding && (
                <PaginatedTable
                  key={`${finding.id}-kms`}
                  title="Customer-managed KMS keys — rotation off"
                  rows={kmsRotRows}
                  columns={[
                    { header: "Region", key: "region" },
                    { header: "Key ID", key: "key_id" },
                    { header: "Description", key: "description" },
                  ]}
                />
              )}

              {openDefSgRows && openDefSgRows.length > 0 && finding && (
                <PaginatedTable
                  key={`${finding.id}-defsg`}
                  title="Default security groups with open ingress"
                  rows={openDefSgRows}
                  columns={[
                    { header: "Region", key: "region" },
                    { header: "Group ID", key: "group_id" },
                    { header: "VPC", key: "vpc_id" },
                    { header: "Ingress rules", key: "ingress_count" },
                    {
                      header: "Open to world?",
                      render: (row) => (row.open_to_world ? "Yes" : "No"),
                    },
                  ]}
                />
              )}

              {mfaUsers && mfaUsers.length > 0 && finding && (
                <PaginatedTable
                  key={`${finding.id}-mfa`}
                  title="IAM users without MFA"
                  subtitle="Account age from CreateDate (green ≤90d, amber ≤365d, red older — indicative only). Large accounts stay responsive via pagination."
                  rows={mfaUsers as Record<string, unknown>[]}
                  pageSize={15}
                  columns={[
                    {
                      header: "User",
                      render: (row) => (
                        <span className="font-mono">
                          {String(row.user_name ?? row.UserName ?? "—")}
                        </span>
                      ),
                    },
                    {
                      header: "Created",
                      render: (row) => fmtTs(row.create_date),
                    },
                    {
                      header: "Age",
                      render: (row) => {
                        const age = row.user_age_days as number | undefined;
                        return (
                          <span
                            className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${ageBadgeClass(age)}`}
                          >
                            {age == null ? "—" : `${age}d`}
                          </span>
                        );
                      },
                    },
                    {
                      header: "Password last used",
                      render: (row) => fmtTs(row.password_last_used),
                    },
                    {
                      header: "Days since pwd use",
                      render: (row) => {
                        const dPwd = row.days_since_password_use as
                          | number
                          | undefined;
                        return (
                          <span
                            className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${ageBadgeClass(dPwd)}`}
                          >
                            {dPwd == null ? "—" : `${dPwd}d`}
                          </span>
                        );
                      },
                    },
                  ]}
                />
              )}

              {s3Buckets && s3Buckets.length > 0 && finding && (
                <PaginatedTable
                  key={`${finding.id}-s3`}
                  title="S3 buckets (Block Public Access)"
                  subtitle="Expand JSON per row for full PublicAccessBlockConfiguration when present."
                  rows={s3Buckets as Record<string, unknown>[]}
                  pageSize={10}
                  columns={[
                    {
                      header: "Bucket",
                      render: (row) => (
                        <span className="font-mono">
                          {String(row.name ?? "—")}
                        </span>
                      ),
                    },
                    {
                      header: "API error / gap",
                      render: (row) => (
                        <span className="text-amber-800 dark:text-amber-200/90">
                          {String(row.public_access_block_error ?? "—")}
                        </span>
                      ),
                    },
                    {
                      header: "PAB config",
                      render: (row) => (
                        <details className="max-w-md">
                          <summary className="cursor-pointer text-aws-orange text-xs mb-1">
                            View JSON
                          </summary>
                          <JsonBlock value={row.public_access_block ?? {}} />
                        </details>
                      ),
                    },
                  ]}
                />
              )}

              {keyConcerns && keyConcerns.length > 0 && finding && (
                <PaginatedTable
                  key={`${finding.id}-keys`}
                  title="Access key rotation (credential report)"
                  subtitle="Flagged when active access key 1 has no meaningful last-used data."
                  rows={keyConcerns as Record<string, unknown>[]}
                  pageSize={15}
                  columns={[
                    {
                      header: "User",
                      render: (row) => (
                        <span className="font-mono">
                          {String(row.user_name ?? "—")}
                        </span>
                      ),
                    },
                    {
                      header: "Key last rotated",
                      render: (row) => fmtTs(row.access_key_1_last_rotated),
                    },
                    {
                      header: "Key age",
                      render: (row) => {
                        const kd = row.key_age_days as number | undefined;
                        return (
                          <span
                            className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${ageBadgeClass(kd)}`}
                          >
                            {kd == null ? "—" : `${kd}d`}
                          </span>
                        );
                      },
                    },
                    {
                      header: "Last used",
                      render: (row) =>
                        String(row.access_key_1_last_used ?? "—"),
                    },
                    {
                      header: "User created",
                      render: (row) => fmtTs(row.user_creation_time),
                    },
                  ]}
                />
              )}

              {evObj && <EvidenceAutoTables evidence={evObj} />}

              <section className="rounded-xl border border-[var(--border)] dash-surface-nested mt-4">
                <details className="group">
                  <summary className="cursor-pointer list-none [&::-webkit-details-marker]:hidden flex flex-wrap items-center justify-between gap-2 px-4 py-3 text-sm font-medium dash-text-primary hover:bg-[var(--panel-hover)]/40 rounded-t-xl transition-colors">
                    <span className="min-w-0">Raw evidence JSON</span>
                    <span className="text-xs font-normal dash-text-muted shrink-0 tabular-nums">
                      <span className="inline group-open:hidden">Show</span>
                      <span className="hidden group-open:inline">Hide</span>
                    </span>
                  </summary>
                  <div className="px-4 pb-4 border-t border-[var(--border)] pt-3 space-y-2">
                    <p className="text-xs dash-text-muted leading-relaxed">
                      Full structured payload returned for this finding. Use for
                      debugging or automation — prefer tables above for review.
                    </p>
                    <JsonBlock value={finding.evidence_json} />
                  </div>
                </details>
              </section>
            </>
          )}
        </SpaceBetween>
      </div>
    </ContentLayout>
  );
}
