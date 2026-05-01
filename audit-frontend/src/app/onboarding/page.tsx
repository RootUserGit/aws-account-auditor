"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

function parseDetail(raw: unknown): string {
  if (typeof raw === "string") return raw;
  if (raw && typeof raw === "object" && "message" in raw && typeof (raw as { message: unknown }).message === "string") {
    return (raw as { message: string }).message;
  }
  return "Request failed";
}

export default function OnboardingPage() {
  const [accountId, setAccountId] = useState("");
  const [roleArn, setRoleArn] = useState("");
  const [externalId, setExternalId] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  /** Platform row UUID for aws_accounts (e.g. ea501131-cc04-42aa-adb6-fcadc88df107) — not the 12-digit AWS account id */
  const [linkedRowId, setLinkedRowId] = useState<string | null>(null);

  async function register() {
    setLoading(true);
    setMessage(null);
    try {
      const res = await fetch("/api/backend/accounts", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          account_id: accountId,
          role_arn: roleArn,
          external_id: externalId,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const detail = data.detail;
        if (res.status === 409 && detail && typeof detail === "object" && "existing_account_row_id" in detail) {
          const rowId = String((detail as { existing_account_row_id: string }).existing_account_row_id);
          setLinkedRowId(rowId);
          setMessage(
            `${parseDetail(detail)} Use the UUID below for Verify/Delete, or delete the row first.`
          );
          return;
        }
        setMessage(parseDetail(detail));
        return;
      }
      const id = typeof data.id === "string" ? data.id : "";
      setLinkedRowId(id);
      setMessage(`Registered AWS account ${data.account_id}. Saved row id (use for Verify): ${id}`);
    } finally {
      setLoading(false);
    }
  }

  async function verify(accountUuid: string) {
    const trimmed = accountUuid.trim();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(trimmed)) {
      setMessage(
        "That does not look like a row UUID. Use the value from Register (format xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx). Do not paste ARNs or tokens with / or +."
      );
      return;
    }
    setLoading(true);
    setMessage(null);
    try {
      const res = await fetch(`/api/backend/accounts/${encodeURIComponent(trimmed)}/verify`, {
        method: "POST",
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setMessage(parseDetail(data.detail));
        return;
      }
      if (data.status === "verified") {
        setMessage("STS AssumeRole succeeded — account marked verified.");
        return;
      }
      if (data.status === "error") {
        const awsCode =
          typeof data.last_verify_error_code === "string"
            ? data.last_verify_error_code
            : "unknown";
        setMessage(
          [
            "HTTP 200 means the API ran; STS still failed — row status is \"error\".",
            `AWS error code: ${awsCode}`,
            "Typical fixes: trust policy must allow your platform IAM principal; ExternalId must match; role ARN must exist.",
          ].join("\n")
        );
        return;
      }
      setMessage(`Account status after verify: ${data.status}`);
    } finally {
      setLoading(false);
    }
  }

  async function removeAccount(accountUuid: string) {
    const trimmed = accountUuid.trim();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(trimmed)) {
      setMessage("Enter a valid row UUID to delete.");
      return;
    }
    setLoading(true);
    setMessage(null);
    try {
      const res = await fetch(`/api/backend/accounts/${encodeURIComponent(trimmed)}`, {
        method: "DELETE",
      });
      if (res.status === 204) {
        setLinkedRowId(null);
        setMessage("Account row deleted. You can Register again with the same AWS account ID.");
        return;
      }
      const data = await res.json().catch(() => ({}));
      setMessage(parseDetail(data.detail));
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 p-8">
      <div className="max-w-xl mx-auto space-y-8">
        <Link href="/" className="text-emerald-400 text-sm hover:underline">
          ← Home
        </Link>
        <h1 className="text-2xl font-semibold">Onboard AWS account</h1>
        <p className="text-xs text-slate-500 leading-relaxed">
          After <strong>Register</strong>, copy the <strong>row UUID</strong> (eight-dash format). Verify calls{" "}
          <code className="text-emerald-300">POST /accounts/{"{uuid}"}/verify</code>. Random strings with{" "}
          <code className="text-emerald-300">/</code> or <code className="text-emerald-300">+</code> are not valid
          UUIDs and will 404.
        </p>
        <div className="space-y-4">
          <label className="block space-y-1">
            <span className="text-sm text-slate-400">Account ID (12 digits)</span>
            <input
              className="w-full rounded-md bg-slate-900 border border-slate-700 px-3 py-2"
              value={accountId}
              onChange={(e) => setAccountId(e.target.value)}
              placeholder="123456789012"
            />
          </label>
          <label className="block space-y-1">
            <span className="text-sm text-slate-400">Auditor role ARN</span>
            <input
              className="w-full rounded-md bg-slate-900 border border-slate-700 px-3 py-2"
              value={roleArn}
              onChange={(e) => setRoleArn(e.target.value)}
              placeholder="arn:aws:iam::123456789012:role/YourAuditorRole"
            />
          </label>
          <label className="block space-y-1">
            <span className="text-sm text-slate-400">External ID</span>
            <input
              className="w-full rounded-md bg-slate-900 border border-slate-700 px-3 py-2"
              value={externalId}
              onChange={(e) => setExternalId(e.target.value)}
            />
          </label>
          <button
            type="button"
            disabled={loading}
            onClick={register}
            className="rounded-lg bg-emerald-500 disabled:opacity-50 text-slate-950 font-medium px-4 py-2"
          >
            Register
          </button>
          <QuickVerify
            initialId={linkedRowId ?? ""}
            onVerify={verify}
            onDelete={removeAccount}
            disabled={loading}
          />
        </div>
        {message && (
          <p className="rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm whitespace-pre-wrap">
            {message}
          </p>
        )}
      </div>
    </main>
  );
}

function QuickVerify({
  initialId,
  onVerify,
  onDelete,
  disabled,
}: {
  initialId: string;
  onVerify: (id: string) => void;
  onDelete: (id: string) => void;
  disabled: boolean;
}) {
  const [id, setId] = useState(initialId);
  useEffect(() => {
    if (initialId) setId(initialId);
  }, [initialId]);

  return (
    <div className="space-y-2">
      <p className="text-xs text-slate-500">Row UUID (from API response field <code className="text-emerald-300">id</code>):</p>
      <input
        className="w-full rounded-md bg-slate-900 border border-slate-700 px-3 py-2 text-sm font-mono"
        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        value={id}
        onChange={(e) => setId(e.target.value)}
      />
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          disabled={disabled || !id.trim()}
          onClick={() => onVerify(id)}
          className="rounded-lg border border-slate-600 px-3 py-2 text-sm"
        >
          Verify STS
        </button>
        <button
          type="button"
          disabled={disabled || !id.trim()}
          onClick={() => onDelete(id)}
          className="rounded-lg border border-red-900 text-red-300 px-3 py-2 text-sm hover:bg-red-950/40"
        >
          Delete this row
        </button>
      </div>
    </div>
  );
}
