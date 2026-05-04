"use client";

import { useEffect, useState } from "react";

import { isHttpOk } from "@/lib/api/http";
import { fetchRun, fetchRunFinding } from "@/services/runs.service";

function scalarStringFromUnknown(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  return "";
}

export type FindingDetailRunMeta = {
  status: string;
  account_id: string;
};

export type FindingDetailFinding = {
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

export function useFindingDetail(runId: string, findingId: string) {
  const [run, setRun] = useState<FindingDetailRunMeta | null>(null);
  const [finding, setFinding] = useState<FindingDetailFinding | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;

    queueMicrotask(() => {
      if (cancelled) return;

      if (!runId || !findingId) {
        setRun(null);
        setFinding(null);
        setErr(null);
        setLoading(false);
        return;
      }

      setLoading(true);
      setErr(null);

      void (async () => {
        try {
          const [rRes, fRes] = await Promise.all([
            fetchRun(runId),
            fetchRunFinding(runId, findingId),
          ]);
          const rData = rRes.data;
          const fData = fRes.data;
          if (cancelled) return;
          if (!isHttpOk(rRes.status) || rData == null) {
            setErr("Could not load run");
            setRun(null);
            setFinding(null);
            return;
          }
          const r = rData as Record<string, unknown>;
          setRun({
            status: scalarStringFromUnknown(r.status),
            account_id: scalarStringFromUnknown(r.account_id),
          });
          if (!isHttpOk(fRes.status) || fData == null) {
            const detail =
              fData &&
              typeof fData === "object" &&
              "detail" in fData &&
              typeof (fData as { detail: unknown }).detail === "string"
                ? (fData as { detail: string }).detail
                : "Finding not found";
            setErr(detail);
            setFinding(null);
            return;
          }
          setFinding(fData as FindingDetailFinding);
          setErr(null);
        } catch {
          if (!cancelled) {
            setErr("Request failed");
            setRun(null);
            setFinding(null);
          }
        } finally {
          if (!cancelled) setLoading(false);
        }
      })();
    });

    return () => {
      cancelled = true;
    };
  }, [runId, findingId]);

  return { run, finding, err, loading };
}
