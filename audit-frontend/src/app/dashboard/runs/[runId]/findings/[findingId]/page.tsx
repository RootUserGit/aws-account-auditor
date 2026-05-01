"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";

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

function JsonBlock({ value }: { value: unknown }) {
  let text: string;
  try {
    text = JSON.stringify(value, null, 2);
  } catch {
    text = String(value);
  }
  return (
    <pre className="text-xs bg-slate-900 border border-slate-800 rounded-md p-4 overflow-auto max-h-[32rem] text-slate-300">
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

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 p-8">
      <div className="max-w-5xl mx-auto space-y-8">
        <div>
          <Link
            href="/dashboard"
            className="text-sm text-emerald-400 hover:underline"
          >
            ← Dashboard
          </Link>
          <h1 className="text-2xl font-semibold mt-3">
            {finding?.check_id ?? "Finding"}
          </h1>
          {run && (
            <p className="text-sm text-slate-400 mt-1">
              Run <code className="text-emerald-300/90">{runId}</code> · Account{" "}
              <code className="text-emerald-300/90">{run.account_id}</code> · Run
              status <span className="capitalize">{run.status}</span>
            </p>
          )}
        </div>

        {err && (
          <p className="text-red-400 text-sm border border-red-900 rounded-md p-3">
            {err}
          </p>
        )}

        {finding && (
          <>
            <section className="flex flex-wrap gap-3 text-sm">
              <span className="rounded border border-slate-700 px-2 py-1 text-slate-300">
                Pillar: {finding.pillar}
              </span>
              <span className="rounded border border-slate-700 px-2 py-1 text-slate-300">
                Severity: {finding.severity}
              </span>
              <span className="rounded border border-slate-700 px-2 py-1 capitalize">
                Status: {finding.status}
              </span>
            </section>

            {finding.remediation_hint && (
              <section className="rounded-lg border border-amber-900/60 bg-amber-950/20 p-4">
                <h2 className="text-sm font-medium text-amber-200/90 mb-2">
                  Remediation
                </h2>
                <p className="text-sm text-amber-100/90">{finding.remediation_hint}</p>
              </section>
            )}

            {mfaUsers && mfaUsers.length > 0 && (
              <section className="space-y-3">
                <h2 className="text-lg font-medium text-slate-200">
                  IAM users without MFA
                </h2>
                <p className="text-sm text-slate-400">
                  Account age from <code className="text-slate-300">CreateDate</code>{" "}
                  (green ≤90d, amber ≤365d, red older — indicative only).
                </p>
                <div className="overflow-x-auto rounded-lg border border-slate-800">
                  <table className="min-w-full text-sm">
                    <thead className="bg-slate-900">
                      <tr>
                        <th className="text-left p-2">User</th>
                        <th className="text-left p-2">Created</th>
                        <th className="text-left p-2">Age</th>
                        <th className="text-left p-2">Password last used</th>
                        <th className="text-left p-2">Days since pwd use</th>
                      </tr>
                    </thead>
                    <tbody>
                      {mfaUsers.map((u, i) => {
                        const name = String(u.user_name ?? u.UserName ?? "—");
                        const age = u.user_age_days as number | undefined;
                        const dPwd = u.days_since_password_use as number | undefined;
                        return (
                          <tr key={`${name}-${i}`} className="border-t border-slate-800">
                            <td className="p-2 font-mono text-xs">{name}</td>
                            <td className="p-2 text-slate-300">{fmtTs(u.create_date)}</td>
                            <td className="p-2">
                              <span
                                className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${ageBadgeClass(age)}`}
                              >
                                {age == null ? "—" : `${age}d`}
                              </span>
                            </td>
                            <td className="p-2 text-slate-300">
                              {fmtTs(u.password_last_used)}
                            </td>
                            <td className="p-2">
                              <span
                                className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${ageBadgeClass(dPwd)}`}
                              >
                                {dPwd == null ? "—" : `${dPwd}d`}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </section>
            )}

            {s3Buckets && s3Buckets.length > 0 && (
              <section className="space-y-3">
                <h2 className="text-lg font-medium text-slate-200">
                  S3 buckets (Block Public Access)
                </h2>
                <div className="overflow-x-auto rounded-lg border border-slate-800">
                  <table className="min-w-full text-sm">
                    <thead className="bg-slate-900">
                      <tr>
                        <th className="text-left p-2">Bucket</th>
                        <th className="text-left p-2">API error / gap</th>
                        <th className="text-left p-2">PAB config</th>
                      </tr>
                    </thead>
                    <tbody>
                      {s3Buckets.map((b, i) => (
                        <tr key={`${String(b.name)}-${i}`} className="border-t border-slate-800 align-top">
                          <td className="p-2 font-mono text-xs">{String(b.name ?? "—")}</td>
                          <td className="p-2 text-amber-200/90">
                            {String(b.public_access_block_error ?? "—")}
                          </td>
                          <td className="p-2">
                            <JsonBlock value={b.public_access_block ?? {}} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            )}

            {keyConcerns && keyConcerns.length > 0 && (
              <section className="space-y-3">
                <h2 className="text-lg font-medium text-slate-200">
                  Access key rotation (credential report)
                </h2>
                <p className="text-sm text-slate-400">
                  Flagged when active access key 1 has no meaningful last-used data. Key
                  age from <code className="text-slate-300">access_key_1_last_rotated</code>.
                </p>
                <div className="overflow-x-auto rounded-lg border border-slate-800">
                  <table className="min-w-full text-sm">
                    <thead className="bg-slate-900">
                      <tr>
                        <th className="text-left p-2">User</th>
                        <th className="text-left p-2">Key last rotated</th>
                        <th className="text-left p-2">Key age</th>
                        <th className="text-left p-2">Last used</th>
                        <th className="text-left p-2">User created</th>
                      </tr>
                    </thead>
                    <tbody>
                      {keyConcerns.map((r, i) => {
                        const kd = r.key_age_days as number | undefined;
                        return (
                          <tr key={`${String(r.user_name)}-${i}`} className="border-t border-slate-800">
                            <td className="p-2 font-mono text-xs">
                              {String(r.user_name ?? "—")}
                            </td>
                            <td className="p-2 text-slate-300">
                              {fmtTs(r.access_key_1_last_rotated)}
                            </td>
                            <td className="p-2">
                              <span
                                className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${ageBadgeClass(kd)}`}
                              >
                                {kd == null ? "—" : `${kd}d`}
                              </span>
                            </td>
                            <td className="p-2 text-slate-300">
                              {String(r.access_key_1_last_used ?? "—")}
                            </td>
                            <td className="p-2 text-slate-300">
                              {fmtTs(r.user_creation_time)}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </section>
            )}

            <section className="rounded-lg border border-slate-800 bg-slate-900/40">
              <details>
                <summary className="cursor-pointer p-3 text-sm font-medium text-slate-300">
                  Raw evidence JSON
                </summary>
                <div className="px-3 pb-3 border-t border-slate-800 pt-3">
                  <JsonBlock value={finding.evidence_json} />
                </div>
              </details>
            </section>
          </>
        )}
      </div>
    </main>
  );
}
