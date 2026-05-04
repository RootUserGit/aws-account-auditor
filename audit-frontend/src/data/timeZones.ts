/**
 * IANA time zones for dashboard display (API timestamps remain UTC).
 * Prefers Intl.supportedValuesOf('timeZone') when available (~full tz database).
 */

export function isValidIanaTimeZone(zone: string): boolean {
  if (!zone || zone === "local") return false;
  try {
    Intl.DateTimeFormat(undefined, { timeZone: zone });
    return true;
  } catch {
    return false;
  }
}

let _allZonesMemo: string[] | null = null;

/** Older environments without Intl.supportedValuesOf('timeZone') */
const FALLBACK_IANA_ZONES: string[] = [
  "Africa/Cairo",
  "Africa/Johannesburg",
  "Africa/Lagos",
  "Africa/Nairobi",
  "America/Argentina/Buenos_Aires",
  "America/Bogota",
  "America/Chicago",
  "America/Denver",
  "America/Los_Angeles",
  "America/Mexico_City",
  "America/New_York",
  "America/Sao_Paulo",
  "America/Toronto",
  "America/Vancouver",
  "Asia/Amman",
  "Asia/Baghdad",
  "Asia/Bangkok",
  "Asia/Beirut",
  "Asia/Colombo",
  "Asia/Dhaka",
  "Asia/Dubai",
  "Asia/Hong_Kong",
  "Asia/Ho_Chi_Minh",
  "Asia/Jakarta",
  "Asia/Jerusalem",
  "Asia/Karachi",
  "Asia/Kolkata",
  "Asia/Kuala_Lumpur",
  "Asia/Kuwait",
  "Asia/Manila",
  "Asia/Muscat",
  "Asia/Qatar",
  "Asia/Riyadh",
  "Asia/Seoul",
  "Asia/Shanghai",
  "Asia/Singapore",
  "Asia/Taipei",
  "Asia/Tehran",
  "Asia/Tokyo",
  "Asia/Yangon",
  "Australia/Adelaide",
  "Australia/Brisbane",
  "Australia/Melbourne",
  "Australia/Perth",
  "Australia/Sydney",
  "Europe/Amsterdam",
  "Europe/Berlin",
  "Europe/Brussels",
  "Europe/Istanbul",
  "Europe/London",
  "Europe/Madrid",
  "Europe/Moscow",
  "Europe/Paris",
  "Europe/Rome",
  "Europe/Stockholm",
  "Europe/Warsaw",
  "Europe/Zurich",
  "Pacific/Auckland",
  "Pacific/Fiji",
  "Pacific/Honolulu",
  "UTC",
];

/** Sorted IANA identifiers (may include UTC / Etc/* depending on engine). */
export function getAllIanaTimeZones(): string[] {
  if (_allZonesMemo) return _allZonesMemo;
  try {
    const sv = Intl.supportedValuesOf as
      | ((this: typeof Intl, key: string) => string[])
      | undefined;
    if (typeof sv === "function") {
      _allZonesMemo = [...sv.call(Intl, "timeZone")].sort((a, b) =>
        a.localeCompare(b),
      );
      return _allZonesMemo;
    }
  } catch {
    /* use fallback */
  }
  _allZonesMemo = [...new Set(FALLBACK_IANA_ZONES)].sort((a, b) =>
    a.localeCompare(b),
  );
  return _allZonesMemo;
}

/** Sample instants (mid-year + winter) so DST naming differences still produce usable labels */
const SEARCH_SAMPLE_TS = [
  Date.UTC(2024, 6, 15, 12, 0, 0),
  Date.UTC(2024, 0, 15, 12, 0, 0),
];

function collectIntlTimeZoneLabels(zone: string): string {
  const seen = new Set<string>();
  const parts: string[] = [];
  for (const ts of SEARCH_SAMPLE_TS) {
    const d = new Date(ts);
    for (const style of ["long", "longGeneric", "shortGeneric"] as const) {
      try {
        const formatted = new Intl.DateTimeFormat("en-US", {
          timeZone: zone,
          timeZoneName: style,
        }).formatToParts(d);
        const v = formatted
          .find((p) => p.type === "timeZoneName")
          ?.value?.trim();
        if (!v || /^gmt[+-]/i.test(v) || /^utc$/i.test(v)) continue;
        const key = v.toLowerCase();
        if (!seen.has(key)) {
          seen.add(key);
          parts.push(v);
        }
      } catch {
        /* skip invalid */
      }
    }
  }
  return parts.join(" ");
}

function ianaWordsBlob(zone: string): string {
  return zone
    .toLowerCase()
    .replace(/[/ _]+/g, " ")
    .trim();
}

type ZoneSearchEntry = {
  zone: string;
  /** Lowercase Intl time zone names (e.g. "India Standard Time", "Jordan Time") */
  displayLower: string;
  /** Lowercase path tokens (e.g. "asia amman") */
  ianaLower: string;
};

let zoneSearchCacheKey: string | null = null;
let zoneSearchCache: Map<string, ZoneSearchEntry> | null = null;

/** Builds per-zone search metadata (memoized for the current full zone list). */
function getZoneSearchEntries(zones: string[]): ZoneSearchEntry[] {
  const key = zones.join("\0");
  if (zoneSearchCacheKey === key && zoneSearchCache) {
    return zones.map((z) => zoneSearchCache!.get(z)!);
  }
  const map = new Map<string, ZoneSearchEntry>();
  for (const zone of zones) {
    map.set(zone, {
      zone,
      displayLower: collectIntlTimeZoneLabels(zone).toLowerCase(),
      ianaLower: ianaWordsBlob(zone),
    });
  }
  zoneSearchCacheKey = key;
  zoneSearchCache = map;
  return zones.map((z) => map.get(z)!);
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function wordBoundaryMatch(haystack: string, word: string): boolean {
  if (!word) return false;
  return new RegExp(`\\b${escapeRegex(word)}\\b`, "i").test(haystack);
}

/**
 * Extra tokens for strict matching (word-boundary), e.g. legacy city spellings.
 */
const SEARCH_TOKEN_ALTERNATES: Record<string, string[]> = {
  calc: ["calcutta", "kolkata"],
  calcutta: ["kolkata"],
};

function alternatesForToken(token: string): string[] {
  return SEARCH_TOKEN_ALTERNATES[token] ?? [];
}

function tokenMatchesStrict(entry: ZoneSearchEntry, token: string): boolean {
  const words = [token, ...alternatesForToken(token)];
  const blob = `${entry.displayLower} ${entry.ianaLower}`;
  return words.some((w) => wordBoundaryMatch(blob, w));
}

/** Prefix match on Intl labels only (e.g. "pakis" → Pakistan Standard Time), avoids Indiana vs India on path tokens */
function tokenMatchesDisplayPrefix(
  displayLower: string,
  token: string,
): boolean {
  if (token.length < 4) return false;
  const words = displayLower.match(/[a-z0-9]+/g) ?? [];
  return words.some((w) => w.startsWith(token));
}

function tokenMatchesEntry(entry: ZoneSearchEntry, token: string): boolean {
  return (
    tokenMatchesStrict(entry, token) ||
    tokenMatchesDisplayPrefix(entry.displayLower, token)
  );
}

function rankMatch(entry: ZoneSearchEntry, tokens: string[]): number {
  let score = 0;
  for (const token of tokens) {
    const words = [token, ...alternatesForToken(token)];
    const hitDisplayBoundary = words.some((w) =>
      wordBoundaryMatch(entry.displayLower, w),
    );
    const hitIanaBoundary = words.some((w) =>
      wordBoundaryMatch(entry.ianaLower, w),
    );
    const hitDisplayPrefix =
      !hitDisplayBoundary &&
      tokenMatchesDisplayPrefix(entry.displayLower, token);

    if (hitDisplayBoundary) score += 100;
    else if (hitDisplayPrefix) score += 60;
    else if (hitIanaBoundary) score += 10;
  }
  return score;
}

/**
 * Filter IANA zones by search query: matches country/city names via Intl labels as well as zone ids.
 * Uses word-boundary matching first so "india" finds India Standard Time, not Indiana.
 */
export function filterIanaZonesBySearch(
  zones: string[],
  query: string,
): string[] {
  const raw = query.trim().toLowerCase();
  if (!raw) return zones;
  const tokens = raw.split(/\s+/).filter(Boolean);
  if (!tokens.length) return zones;

  const entries = getZoneSearchEntries(zones);
  const strictHits: string[] = [];
  for (let i = 0; i < zones.length; i++) {
    const z = zones[i];
    const e = entries[i];
    if (tokens.every((t) => tokenMatchesEntry(e, t))) strictHits.push(z);
  }

  if (strictHits.length > 0) {
    const entryByZone = new Map(entries.map((e) => [e.zone, e]));
    return [...strictHits].sort((a, b) => {
      const ra = rankMatch(entryByZone.get(a)!, tokens);
      const rb = rankMatch(entryByZone.get(b)!, tokens);
      if (rb !== ra) return rb - ra;
      return a.localeCompare(b);
    });
  }

  const fallback = zones.filter((z) =>
    tokens.every((t) => z.toLowerCase().includes(t)),
  );
  return fallback.sort((a, b) => a.localeCompare(b));
}

/** Trigger button label — AWS-style: technical id, presets spelled out */
export function formatDisplayTzLabel(value: string): string {
  if (value === "local") return "Browser default";
  if (value === "UTC") return "UTC";
  if (isValidIanaTimeZone(value)) return value;
  return "Browser default";
}
