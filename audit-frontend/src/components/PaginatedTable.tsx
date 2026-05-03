"use client";

import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

export type TableColumn = {
  header: string;
  /** Dot path optional later; for now flat keys on row */
  key?: string;
  /** Custom cell when key isn't enough */
  render?: (row: Record<string, unknown>) => ReactNode;
};

function cellValue(row: Record<string, unknown>, key: string | undefined, render: TableColumn["render"]) {
  if (render) return render(row);
  if (!key) return "—";
  const v = row[key];
  if (v == null || v === "") return "—";
  return String(v);
}

export function PaginatedTable({
  title,
  subtitle,
  columns,
  rows,
  pageSize = 10,
  emptyMessage = "No rows in this sample.",
}: {
  title: string;
  subtitle?: string;
  columns: TableColumn[];
  rows: Record<string, unknown>[];
  pageSize?: number;
  emptyMessage?: string;
}) {
  const [page, setPage] = useState(0);
  const total = rows.length;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));

  useEffect(() => {
    queueMicrotask(() => {
      setPage((p) => Math.min(p, Math.max(0, pageCount - 1)));
    });
  }, [pageCount, rows.length]);

  const pageRows = useMemo(() => {
    const start = page * pageSize;
    return rows.slice(start, start + pageSize);
  }, [rows, page, pageSize]);

  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-lg font-medium text-white tracking-tight">{title}</h2>
        {subtitle && <p className="text-xs text-slate-500 mt-1 leading-relaxed">{subtitle}</p>}
      </div>
      {total === 0 ? (
        <p className="text-sm text-slate-500 border border-dashed border-[var(--border)] rounded-xl p-6 text-center">
          {emptyMessage}
        </p>
      ) : (
        <>
          <div className="overflow-x-auto rounded-xl border border-[var(--border)] bg-[var(--panel)]/40">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs uppercase tracking-wide text-slate-500">
                  {columns.map((c) => (
                    <th key={c.header} className="p-3 font-medium whitespace-nowrap">
                      {c.header}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {pageRows.map((row, ri) => (
                  <tr key={ri} className="border-t border-[var(--border)]/80 hover:bg-[var(--panel-hover)]/50">
                    {columns.map((c) => (
                      <td key={c.header} className="p-3 text-slate-300 align-top text-xs">
                        {cellValue(row, c.key, c.render)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {total > pageSize && (
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
              <span>
                Showing {page * pageSize + 1}–{Math.min((page + 1) * pageSize, total)} of {total}
              </span>
              <div className="flex gap-2">
                <button
                  type="button"
                  disabled={page <= 0}
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  className="rounded-md border border-[var(--border)] px-3 py-1.5 hover:bg-[var(--panel-hover)] disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Previous
                </button>
                <button
                  type="button"
                  disabled={page >= pageCount - 1}
                  onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
                  className="rounded-md border border-[var(--border)] px-3 py-1.5 hover:bg-[var(--panel-hover)] disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </section>
  );
}
