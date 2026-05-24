import type { Account } from "@/lib/types/dashboard";

/** Case-normalized key for exact tag matching (prod ≠ production). */
export function environmentKey(tag: string): string {
  return tag.trim().toLowerCase();
}

/** Sentinel for the dashboard environment filter “show all accounts”. */
export const DASHBOARD_ENVIRONMENT_FILTER_ALL = "__all__" as const;

/**
 * Options for the dashboard environment filter: **All**, then distinct
 * non-default tags from onboarded accounts (excludes stored `other`).
 */
export function userEnvironmentSelectOptionsFromAccounts(
  accounts: readonly Account[],
): { label: string; value: string }[] {
  const seen = new Set<string>();
  const tags: { label: string; value: string }[] = [];
  for (const a of accounts) {
    const k = environmentKey(a.environment);
    if (!k || k === "other") continue;
    if (seen.has(k)) continue;
    seen.add(k);
    tags.push({ label: k, value: k });
  }
  tags.sort((a, b) => a.label.localeCompare(b.label));
  return [
    { label: "All", value: DASHBOARD_ENVIRONMENT_FILTER_ALL },
    ...tags,
  ];
}

/** Single-select filter: All → every account; otherwise exact tag match (case-insensitive). */
export function accountMatchesEnvironmentSelect(
  account: Account,
  selectedValue: string | undefined,
): boolean {
  if (
    selectedValue == null ||
    selectedValue === "" ||
    selectedValue === DASHBOARD_ENVIRONMENT_FILTER_ALL
  ) {
    return true;
  }
  return environmentKey(account.environment) === environmentKey(selectedValue);
}

/** Badge / table display: default stored tag `other` shows as “-”. */
export function environmentBadgeLabel(environment: string): string {
  const k = environmentKey(environment);
  return k === "other" ? "-" : k;
}
