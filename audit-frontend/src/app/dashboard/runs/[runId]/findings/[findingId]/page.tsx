"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";

import { EvidenceAutoTables } from "@/components/EvidenceAutoTables";
import { PaginatedTable } from "@/components/PaginatedTable";
import { SiteHeader } from "@/components/SiteHeader";

type Finding = {
  id: string;
  check_id: string;
  pillar: string;
  severity: string;
  status: string;
  war_theme: string | null;
  resource_id: string | null;
  evidence_json: Record<string, unknown> | unknown[] | null;
  remediation_hint: string | null;
};

type RunMeta = {
  status: string;
  account_id: string;
};

function ageBadgeClass(days: number | null | undefined): string {
  if (days == null || Number.isNaN(days)) {
    return "bg-slate-800 text-slate-400 border border-slate-600";
  }
  if (days <= 90) {
    return "bg-emerald-950 text-emerald-300 border border-emerald-800";
  }
  if (days <= 365) {
    return "bg-amber-950 text-amber-200 border border-amber-800";
  }
  return "bg-red-950 text-red-200 border border-red-800";
}

function fmtTs(v: unknown): string {
  if (v == null) return "—";
  if (typeof v === "string") return v;
  return String(v);
}

function asRecordArray(v: unknown): Record<string, unknown>[] | null {
  if (!Array.isArray(v) || v.length === 0) return null;
  if (!v.every((x) => x && typeof x === "object" && !Array.isArray(x))) return null;
  return v as Record<string, unknown>[];
}

/** Format ISO-ish launch times from the API / boto serialization */
function fmtLaunch(v: unknown): string {
  if (v == null || v === "") return "—";
  if (typeof v === "string") {
    const ms = Date.parse(v);
    if (!Number.isNaN(ms)) return new Date(ms).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
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

function JsonBlock({ value }: { value: unknown }) {
  let text: string;
  try {
    text = JSON.stringify(value, null, 2);
  } catch {
    text = String(value);
  }
  return (
    <pre className="text-xs bg-[var(--panel)] border border-[var(--border)] rounded-lg p-4 overflow-auto max-h-[32rem] text-slate-300 font-mono">
      {text}
    </pre>
  );
}

export default function FindingDetailPage() {
  const params = useParams<{ runId: string; findingId: string }>();
  const runId = params.runId ?? "";
  const findingId = params.findingId ?? "";

  const [run, setRun] = useState<RunMeta | null>(null);
  const [finding, setFinding] = useState<Finding | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!runId || !findingId) return;
    let cancelled = false;
    (async () => {
      setErr(null);
      try {
        const [rRes, fRes] = await Promise.all([
          fetch(`/api/backend/runs/${runId}`, { cache: "no-store" }),
          fetch(`/api/backend/runs/${runId}/findings/${findingId}`, {
            cache: "no-store",
          }),
        ]);
        const rData = await rRes.json().catch(() => null);
        const fData = await fRes.json().catch(() => null);
        if (cancelled) return;
        if (!rRes.ok || !rData) {
          setErr("Could not load run");
          return;
        }
        if (!fRes.ok || !fData) {
          setErr(
            typeof fData?.detail === "string"
              ? fData.detail
              : "Finding not found"
          );
          return;
        }
        setRun({
          status: String(rData.status ?? ""),
          account_id: String(rData.account_id ?? ""),
        });
        setFinding(fData as Finding);
      } catch {
        if (!cancelled) setErr("Request failed");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [runId, findingId]);

  const ev = finding?.evidence_json;
  const evObj = ev && typeof ev === "object" && !Array.isArray(ev) ? (ev as Record<string, unknown>) : null;

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
    ? (evObj.remediation_playbook as unknown[]).filter((x): x is string => typeof x === "string")
    : [];

  const sshOpenRows = asRecordArray(evObj?.open_ssh_security_groups);
  const stoppedInstRows = asRecordArray(evObj?.stopped_instances_sample);
  const eipRows = asRecordArray(evObj?.unassociated_elastic_ips);
  const volumeRows = asRecordArray(evObj?.unattached_volumes);
  const rdsBadRows = asRecordArray(evObj?.non_compliant_instances);
  const adminUserRows = asRecordArray(evObj?.users_with_administrator_access);
  const kmsRotRows = asRecordArray(evObj?.keys_without_rotation);
  const openDefSgRows = asRecordArray(evObj?.open_default_sgs);

  return (
    <div className="min-h-screen flex flex-col">
      <SiteHeader
        nav={[
          { href: "/", label: "Home" },
          { href: "/dashboard", label: "Dashboard" },
        ]}
      />
      <main className="flex-1 max-w-5xl mx-auto w-full px-4 sm:px-6 py-8 space-y-8">
        <div>
          <Link href="/dashboard" className="text-sm text-aws-orange hover:underline">
            ← Dashboard
          </Link>
          <h1 className="text-2xl font-semibold mt-3 text-white tracking-tight">
            {finding?.check_id ?? "Finding"}
          </h1>
          {run && (
            <p className="text-sm text-slate-400 mt-1">
              Run <code className="text-aws-orange/90 font-mono text-xs">{runId}</code> · Account{" "}
              <code className="text-aws-orange/90 font-mono text-xs">{run.account_id}</code> · Run status{" "}
              <span className="capitalize">{run.status}</span>
            </p>
          )}
        </div>

        {err && (
          <p className="text-red-300 text-sm border border-red-900/60 bg-red-950/30 rounded-lg p-3">{err}</p>
        )}

        {finding && (
          <>
            <section className="flex flex-wrap gap-3 text-sm">
              <span className="rounded-lg border border-[var(--border)] px-3 py-1 text-slate-300 bg-[var(--panel)]/60">
                Pillar: {finding.pillar}
              </span>
              <span className="rounded-lg border border-[var(--border)] px-3 py-1 text-slate-300 bg-[var(--panel)]/60">
                Severity: {finding.severity}
              </span>
              <span className="rounded-lg border border-[var(--border)] px-3 py-1 capitalize text-slate-200 bg-[var(--panel)]/60">
                Status: {finding.status}
              </span>
            </section>

            {finding.status === "unknown" &&
              evObj &&
              typeof evObj.error === "string" &&
              evObj.error.startsWith("unknown_evaluator:") && (
                <section
                  className="rounded-xl border border-amber-700/45 bg-amber-950/30 p-5 space-y-2"
                  role="alert"
                >
                  <h2 className="text-xs font-medium uppercase tracking-wider text-amber-200/95">
                    Rule could not run on the worker
                  </h2>
                  <p className="text-sm text-slate-200 leading-relaxed">
                    The audit worker received this check from the rule pack, but its Python process does not register an
                    evaluator named{" "}
                    <code className="text-amber-100/90 font-mono text-xs">{String(evObj.error).replace(/^unknown_evaluator:/, "")}</code>.
                    That almost always means the{" "}
                    <strong className="font-medium text-slate-100">worker container or package is outdated</strong> —
                    rebuild and redeploy <span className="font-mono text-slate-300">audit-worker</span> from the same
                    commit as <span className="font-mono text-slate-300">audit-agents</span>, then run a new scan.
                  </p>
                </section>
              )}

            {finding.remediation_hint &&
              !(typeof evObj?.error === "string" && evObj.error.startsWith("unknown_evaluator:")) && (
              <section className="rounded-xl border border-aws-orange/35 bg-aws-orange/5 p-5">
                <h2 className="text-xs font-medium uppercase tracking-wider text-aws-orange mb-2">
                  Remediation summary
                </h2>
                <p className="text-sm text-slate-200 leading-relaxed">{finding.remediation_hint}</p>
              </section>
            )}

            {finding.remediation_hint &&
              typeof evObj?.error === "string" &&
              evObj.error.startsWith("unknown_evaluator:") && (
                <section className="rounded-xl border border-slate-600/50 bg-[var(--panel)]/50 p-4">
                  <p className="text-xs text-slate-500">
                    Generic remediation text is hidden for this row because the check did not execute — fix the worker
                    version first.
                  </p>
                </section>
              )}

            {playbook.length > 0 && (
              <section className="rounded-xl border border-[var(--border)] bg-[var(--panel)]/60 p-5 space-y-3">
                <h2 className="text-xs font-medium uppercase tracking-wider text-slate-400">
                  Production remediation playbook
                </h2>
                <ol className="list-decimal list-inside space-y-3 text-sm text-slate-300 leading-relaxed">
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
                    render: (row) => <span className="font-mono">{portRangeLabel(row)}</span>,
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
                  { header: "Launched", render: (row) => fmtLaunch(row.launch_time) },
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
                  { header: "Open to world?", render: (row) => (row.open_to_world ? "Yes" : "No") },
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
                      <span className="font-mono">{String(row.user_name ?? row.UserName ?? "—")}</span>
                    ),
                  },
                  { header: "Created", render: (row) => fmtTs(row.create_date) },
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
                  { header: "Password last used", render: (row) => fmtTs(row.password_last_used) },
                  {
                    header: "Days since pwd use",
                    render: (row) => {
                      const dPwd = row.days_since_password_use as number | undefined;
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
                    render: (row) => <span className="font-mono">{String(row.name ?? "—")}</span>,
                  },
                  {
                    header: "API error / gap",
                    render: (row) => (
                      <span className="text-amber-200/90">{String(row.public_access_block_error ?? "—")}</span>
                    ),
                  },
                  {
                    header: "PAB config",
                    render: (row) => (
                      <details className="max-w-md">
                        <summary className="cursor-pointer text-aws-orange text-xs mb-1">View JSON</summary>
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
                    render: (row) => <span className="font-mono">{String(row.user_name ?? "—")}</span>,
                  },
                  { header: "Key last rotated", render: (row) => fmtTs(row.access_key_1_last_rotated) },
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
                  { header: "Last used", render: (row) => String(row.access_key_1_last_used ?? "—") },
                  { header: "User created", render: (row) => fmtTs(row.user_creation_time) },
                ]}
              />
            )}

            {evObj && <EvidenceAutoTables evidence={evObj} />}

            <section className="rounded-xl border border-[var(--border)] bg-[#0c1117]/60">
              <details>
                <summary className="cursor-pointer p-3 text-sm font-medium text-slate-300 list-none [&::-webkit-details-marker]:hidden">
                  Raw evidence JSON (advanced)
                </summary>
                <div className="px-3 pb-3 border-t border-[var(--border)] pt-3">
                  <JsonBlock value={finding.evidence_json} />
                </div>
              </details>
            </section>
          </>
        )}
      </main>
    </div>
  );
}
