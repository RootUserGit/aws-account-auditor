"use client";

import { useMemo } from "react";

import { PaginatedTable } from "@/components/PaginatedTable";

/** Keys rendered with bespoke columns elsewhere on the finding detail page */
const HANDLED_EVIDENCE_KEYS = new Set([
  "users_without_mfa",
  "buckets_detail",
  "access_key_concerns",
  "open_ssh_security_groups",
  "stopped_instances_sample",
  "unassociated_elastic_ips",
  "unattached_volumes",
  "non_compliant_instances",
  "users_with_administrator_access",
  "keys_without_rotation",
  "open_default_sgs",
]);

function humanizeKey(key: string): string {
  return key
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .trim();
}

function isPlainObjectRowArray(v: unknown): v is Record<string, unknown>[] {
  if (!Array.isArray(v) || v.length === 0) return false;
  return v.every((x) => x !== null && typeof x === "object" && !Array.isArray(x));
}

function formatCellValue(v: unknown): string {
  if (v == null) return "—";
  if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") return String(v);
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

const COLUMN_PRIORITY = [
  "region",
  "availability_zone",
  "zone",
  "instance_id",
  "instance_type",
  "image_id",
  "vpc_id",
  "subnet_id",
  "group_id",
  "group_name",
  "role_name",
  "user_name",
  "name",
  "check_id",
  "severity",
  "status",
  "principal",
  "arn",
  "allocation_id",
  "volume_id",
  "db_instance_identifier",
];

function inferColumns(rows: Record<string, unknown>[]): { header: string; key: string }[] {
  const keys = new Set<string>();
  for (const row of rows.slice(0, 40)) {
    Object.keys(row).forEach((k) => keys.add(k));
  }
  const ordered: string[] = [];
  for (const k of COLUMN_PRIORITY) {
    if (keys.has(k)) ordered.push(k);
  }
  for (const k of [...keys].sort()) {
    if (!ordered.includes(k)) ordered.push(k);
  }
  return ordered.map((k) => ({ header: humanizeKey(k), key: k }));
}

export function EvidenceAutoTables({ evidence }: { evidence: Record<string, unknown> | null }) {
  const sections = useMemo(() => {
    if (!evidence) return [];
    const out: { key: string; title: string; rows: Record<string, unknown>[] }[] = [];
    for (const [k, v] of Object.entries(evidence)) {
      if (k === "remediation_playbook" || k === "error") continue;
      if (HANDLED_EVIDENCE_KEYS.has(k)) continue;
      if (!isPlainObjectRowArray(v)) continue;
      out.push({ key: k, title: humanizeKey(k), rows: v });
    }
    return out;
  }, [evidence]);

  if (sections.length === 0) return null;

  return (
    <div className="space-y-8">
      {sections.map(({ key, title, rows }) => (
        <PaginatedTable
          key={key}
          title={title}
          subtitle={`Evidence field: ${key}`}
          rows={rows}
          pageSize={12}
          columns={inferColumns(rows).map((c) => ({
            header: c.header,
            key: c.key,
            render: (row) => (
              <span className="font-mono text-[11px] leading-snug break-all">{formatCellValue(row[c.key])}</span>
            ),
          }))}
        />
      ))}
    </div>
  );
}
