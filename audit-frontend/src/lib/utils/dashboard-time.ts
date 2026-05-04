import { DISPLAY_TZ_STORAGE_KEY } from "@/lib/constants/dashboard";
import { isValidIanaTimeZone } from "@/data/timeZones";

export function optimisticEnqueueRowId(platformAccountUuid: string): string {
  return `pending:${platformAccountUuid}`;
}

export function browserDefaultTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

export function resolveDisplayTimeZone(tzKey: string): string {
  if (tzKey === "local" || tzKey === "") return browserDefaultTimeZone();
  return tzKey;
}

export function fmtAuditInstant(iso: string | null, tzKey: string): string {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    const iana = resolveDisplayTimeZone(tzKey);
    return d.toLocaleString(undefined, {
      timeZone: iana,
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
      hour12: true,
      timeZoneName: "short",
    });
  } catch {
    return iso;
  }
}

export function readStoredDisplayTz(): string {
  if (typeof window === "undefined") return "local";
  try {
    const raw = localStorage.getItem(DISPLAY_TZ_STORAGE_KEY);
    if (!raw) return "local";
    if (raw === "local" || raw === "UTC") return raw;
    if (isValidIanaTimeZone(raw)) return raw;
  } catch {
    /* ignore */
  }
  return "local";
}

export function formatDurationMs(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const secTotal = Math.floor(ms / 1000);
  const days = Math.floor(secTotal / 86400);
  const hours = Math.floor((secTotal % 86400) / 3600);
  const minutes = Math.floor((secTotal % 3600) / 60);
  const seconds = secTotal % 60;
  if (days >= 1) {
    return `${days}:${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}`;
  }
  if (secTotal >= 3600) {
    return `${hours}:${String(minutes).padStart(2, "0")}`;
  }
  return `${minutes}:${String(seconds).padStart(2, "0")}`;
}

export function parseIsoMs(iso: string | null): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : null;
}
