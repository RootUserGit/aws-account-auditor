"use client";

import { useMemo, useState } from "react";

import {
  filterIanaZonesBySearch,
  formatDisplayTzLabel,
  getAllIanaTimeZones,
} from "@/data/timeZones";

const PAGE_SIZE = 16;

type Props = {
  value: string;
  onChange: (ianaOrPreset: string) => void;
  className?: string;
};

export function TimeZonePicker({ value, onChange, className }: Props) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);

  const allZones = useMemo(() => getAllIanaTimeZones(), []);

  const filtered = useMemo(() => filterIanaZonesBySearch(allZones, query), [allZones, query]);

  const maxPage = Math.max(0, Math.ceil(filtered.length / PAGE_SIZE) - 1);
  const clampedPage = Math.min(page, maxPage);
  const slice = filtered.slice(clampedPage * PAGE_SIZE, clampedPage * PAGE_SIZE + PAGE_SIZE);

  function pick(next: string) {
    onChange(next);
    setOpen(false);
    setQuery("");
    setPage(0);
  }

  return (
    <div className={`relative ${className ?? ""}`}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-[min(100%,16rem)] items-center justify-between gap-2 rounded border border-[var(--border)] bg-[var(--panel)] px-2 py-1 text-left text-[11px] text-slate-200 hover:bg-[var(--panel-hover)]"
        aria-expanded={open}
        aria-haspopup="listbox"
      >
        <span className="truncate font-mono">{formatDisplayTzLabel(value)}</span>
        <span className="text-slate-500 shrink-0 text-[9px]" aria-hidden>
          {open ? "▴" : "▾"}
        </span>
      </button>

      {open ? (
        <>
          <button
            type="button"
            className="fixed inset-0 z-[60] cursor-default bg-black/10"
            aria-label="Close timezone menu"
            onClick={() => setOpen(false)}
          />
          <div
            className="absolute right-0 top-[calc(100%+3px)] z-[70] w-[min(100vw-1rem,18rem)] rounded border border-[var(--border)] bg-[var(--panel)] py-1.5 shadow-lg"
            role="dialog"
            aria-label="Select time zone"
          >
            <div className="px-2 pb-1.5">
              <input
                type="search"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setPage(0);
                }}
                placeholder="Country, city, or zone id…"
                className="w-full rounded border border-[var(--border)] bg-[var(--background)] px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-600"
                autoComplete="off"
                autoFocus
              />
            </div>

            <div className="flex gap-1.5 border-b border-[var(--border)]/70 px-2 pb-1.5">
              <button
                type="button"
                onClick={() => pick("local")}
                className={`flex-1 rounded px-2 py-1 text-[11px] ${
                  value === "local"
                    ? "bg-white/10 text-white"
                    : "text-slate-400 hover:bg-white/5 hover:text-slate-200"
                }`}
              >
                Browser default
              </button>
              <button
                type="button"
                onClick={() => pick("UTC")}
                className={`flex-1 rounded px-2 py-1 font-mono text-[11px] ${
                  value === "UTC"
                    ? "bg-white/10 text-white"
                    : "text-slate-400 hover:bg-white/5 hover:text-slate-200"
                }`}
              >
                UTC
              </button>
            </div>

            <ul className="border-b border-[var(--border)]/50">
              {slice.length === 0 ? (
                <li className="px-2 py-3 text-center text-[11px] text-slate-500">No matches</li>
              ) : (
                slice.map((z) => (
                  <li key={z}>
                    <button
                      type="button"
                      onClick={() => pick(z)}
                      className={`w-full px-2 py-1 text-left font-mono text-[11px] hover:bg-white/5 ${
                        value === z ? "bg-white/10 text-white" : "text-slate-400"
                      }`}
                    >
                      {z}
                    </button>
                  </li>
                ))
              )}
            </ul>

            {filtered.length > PAGE_SIZE ? (
              <div className="flex justify-end gap-1 px-2 pt-1.5">
                <button
                  type="button"
                  disabled={clampedPage <= 0}
                  onClick={() => setPage((p) => Math.max(0, Math.min(p, maxPage) - 1))}
                  className="rounded px-2 py-0.5 text-[10px] text-slate-500 hover:bg-white/5 hover:text-slate-300 disabled:opacity-30"
                >
                  Prev
                </button>
                <button
                  type="button"
                  disabled={clampedPage >= maxPage}
                  onClick={() => setPage((p) => Math.min(maxPage, Math.min(p, maxPage) + 1))}
                  className="rounded px-2 py-0.5 text-[10px] text-slate-500 hover:bg-white/5 hover:text-slate-300 disabled:opacity-30"
                >
                  Next
                </button>
              </div>
            ) : null}
          </div>
        </>
      ) : null}
    </div>
  );
}
