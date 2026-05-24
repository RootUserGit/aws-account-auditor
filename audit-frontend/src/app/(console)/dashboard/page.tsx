"use client";

import BreadcrumbGroup from "@cloudscape-design/components/breadcrumb-group";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import SpaceBetween from "@cloudscape-design/components/space-between";
import { useCallback, useEffect, useMemo, useState } from "react";
import dynamic from "next/dynamic";
import { useRouter } from "next/navigation";

import {
  DashboardAccountsSummary,
  DashboardErrorBanner,
} from "@/components/dashboard";
import { InlineLoader } from "@/components/InlineLoader";

const DashboardAccountsCards = dynamic(
  () =>
    import("@/components/dashboard/DashboardAccountsCards").then(
      (m) => m.DashboardAccountsCards,
    ),
  {
    ssr: false,
    loading: () => (
      <div className="flex min-h-[14rem] w-full items-center justify-center rounded-[var(--border-radius-container)] border border-[var(--color-border-divider-default)] bg-[var(--color-background-container-content)] py-12">
        <InlineLoader label="Loading accounts…" size="md" />
      </div>
    ),
  },
);

import { useApi } from "@/hooks";
import { isHttpOk } from "@/lib/api/http";
import { HISTORY_PAGE_SIZE } from "@/lib/constants/dashboard";
import type { Account, ScanHistoryRow } from "@/lib/types/dashboard";
import { normalizeAccount, normalizeScanHistoryRow } from "@/lib/utils/dashboard-normalize";

function DashboardOverviewContent() {
  const router = useRouter();
  const api = useApi();
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [accountsLoading, setAccountsLoading] = useState(true);
  const [scanHistory, setScanHistory] = useState<ScanHistoryRow[]>([]);
  const [scanHistoryLoading, setScanHistoryLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const activeScanAccountIds = useMemo(() => {
    const ids = new Set<string>();
    for (const row of scanHistory) {
      const st = row.status?.toLowerCase() ?? "";
      if (st === "queued" || st === "running") ids.add(row.platform_account_id);
    }
    return ids;
  }, [scanHistory]);

  function accountScanBlocked(platformAccountId: string): boolean {
    return activeScanAccountIds.has(platformAccountId);
  }

  const loadRunsSnapshot = useCallback(async () => {
    setScanHistoryLoading(true);
    try {
      const res = await api.fetchRunsList(0, HISTORY_PAGE_SIZE);
      if (!isHttpOk(res.status)) return;
      const rows = res.data;
      if (!Array.isArray(rows)) return;
      const parsed = (rows as unknown[])
        .map(normalizeScanHistoryRow)
        .filter((r): r is ScanHistoryRow => r !== null);
      setScanHistory(parsed);
    } catch {
      /* ignore */
    } finally {
      setScanHistoryLoading(false);
    }
  }, [api]);

  useEffect(() => {
    let cancelled = false;
    queueMicrotask(() => {
      if (!cancelled) setAccountsLoading(true);
    });
    api
      .fetchAccounts()
      .then((r) => {
        const data = r.data ?? null;
        if (!isHttpOk(r.status)) {
          setAccounts([]);
          if (r.status === 401) {
            setErr(
              "API returned 401 — set AUDIT_API_KEY in audit-frontend/.env.local to match the audit-api key (see README local development).",
            );
          } else {
            setErr("Failed to load accounts");
          }
          return;
        }
        if (Array.isArray(data)) {
          setAccounts(
            (data as unknown[])
              .map(normalizeAccount)
              .filter((a): a is Account => a !== null),
          );
          setErr(null);
        } else {
          setAccounts([]);
          setErr("Unexpected accounts response");
        }
      })
      .catch(() => {
        setAccounts([]);
        setErr("Failed to load accounts");
      })
      .finally(() => {
        if (!cancelled) setAccountsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [api]);

  useEffect(() => {
    let cancelled = false;
    queueMicrotask(() => {
      if (cancelled) return;
      void loadRunsSnapshot();
    });
    return () => {
      cancelled = true;
    };
  }, [loadRunsSnapshot]);

  const onBreadcrumbFollow = useCallback(
    (event: CustomEvent) => {
      event.preventDefault();
      const href = (event.detail as { href?: string }).href;
      if (href) router.push(href);
    },
    [router],
  );

  return (
    <ContentLayout
      breadcrumbs={
        <BreadcrumbGroup
          items={[
            { text: "Welcome", href: "/" },
            { text: "Operations dashboard", href: "/dashboard" },
          ]}
          onFollow={onBreadcrumbFollow}
        />
      }
      maxContentWidth={1440}
      header={
        <Header
          variant="h1"
          description="High-level view of onboarded accounts. Open a card to see scan history, start audits, and drill into findings for that account."
        >
          Operations dashboard
        </Header>
      }
    >
      <div className="dashboard-tailwind-surface w-full min-w-0 max-w-full">
        <SpaceBetween size="xl" direction="vertical">
          {err ? <DashboardErrorBanner message={err} /> : null}

          <DashboardAccountsSummary
            accounts={accounts}
            scanHistory={scanHistory}
            loadingAccounts={accountsLoading}
            loadingRuns={scanHistoryLoading}
            onOpenAccount={(id) =>
              router.push(`/dashboard/accounts/${encodeURIComponent(id)}`)
            }
          />

          <DashboardAccountsCards
            accounts={accounts}
            accountScanBlocked={accountScanBlocked}
            loading={accountsLoading}
            onOpenAccount={(id) =>
              router.push(`/dashboard/accounts/${encodeURIComponent(id)}`)
            }
          />
        </SpaceBetween>
      </div>
    </ContentLayout>
  );
}

export default function DashboardPage() {
  return <DashboardOverviewContent />;
}
