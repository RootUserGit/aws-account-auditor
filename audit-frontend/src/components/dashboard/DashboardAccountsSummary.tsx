"use client";

import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import ColumnLayout from "@cloudscape-design/components/column-layout";
import Container from "@cloudscape-design/components/container";
import Header from "@cloudscape-design/components/header";
import Modal from "@cloudscape-design/components/modal";
import SpaceBetween from "@cloudscape-design/components/space-between";
import { useCallback, useMemo, useState } from "react";

import type { Account, ScanHistoryRow } from "@/lib/types/dashboard";

export type DashboardAccountsSummaryProps = {
  accounts: readonly Account[];
  scanHistory: readonly ScanHistoryRow[];
  loadingAccounts?: boolean;
  loadingRuns?: boolean;
  onOpenAccount: (platformAccountUuid: string) => void;
};

type ActiveScanAccountRow = {
  platformId: string;
  awsAccountId: string;
  displayLabel: string;
  runLabels: string[];
};

export function DashboardAccountsSummary({
  accounts,
  scanHistory,
  loadingAccounts = false,
  loadingRuns = false,
  onOpenAccount,
}: Readonly<DashboardAccountsSummaryProps>) {
  const [activeModalOpen, setActiveModalOpen] = useState(false);

  const verified = accounts.filter(
    (a) => (a.status ?? "").toLowerCase() === "verified",
  ).length;
  const pending = accounts.filter(
    (a) => (a.status ?? "").toLowerCase() === "pending",
  ).length;
  const error = accounts.filter(
    (a) => (a.status ?? "").toLowerCase() === "error",
  ).length;

  const inFlight = scanHistory.filter((r) => {
    const s = (r.status ?? "").toLowerCase();
    return s === "queued" || s === "running";
  }).length;

  const activeScanAccountRows = useMemo((): ActiveScanAccountRow[] => {
    const inflight = scanHistory.filter((r) => {
      const s = (r.status ?? "").toLowerCase();
      return s === "queued" || s === "running";
    });
    const byPlatform = new Map<string, ScanHistoryRow[]>();
    for (const r of inflight) {
      const list = byPlatform.get(r.platform_account_id) ?? [];
      list.push(r);
      byPlatform.set(r.platform_account_id, list);
    }
    return [...byPlatform.entries()]
      .filter(([platformId]) => platformId.length > 0)
      .map(([platformId, rows]) => {
      const acc = accounts.find((a) => a.id === platformId);
      const awsAccountId = rows[0]?.aws_account_id ?? acc?.account_id ?? "—";
      const displayLabel =
        acc?.display_name?.trim() ||
        acc?.account_id ||
        awsAccountId;
      const runLabels = rows.map((row) => row.status);
      return {
        platformId,
        awsAccountId,
        displayLabel,
        runLabels,
      };
    });
  }, [accounts, scanHistory]);

  const busy = loadingAccounts || loadingRuns;

  const openActiveModal = useCallback(() => {
    if (!busy && inFlight > 0) setActiveModalOpen(true);
  }, [busy, inFlight]);

  const goToAccount = useCallback(
    (platformId: string) => {
      onOpenAccount(platformId);
      setActiveModalOpen(false);
    },
    [onOpenAccount],
  );

  return (
    <>
      <Container
        header={
          <Header
            variant="h2"
            description="Snapshot across all onboarded accounts. Open an account card for scan history, start a run, and findings."
          >
            Accounts overview
          </Header>
        }
      >
        <ColumnLayout columns={3} variant="text-grid" minColumnWidth={180}>
          <div>
            <Box variant="awsui-key-label">Connected</Box>
            <Box variant="h1" margin={{ top: "xxs" }}>
              {busy ? "—" : accounts.length}
            </Box>
          </div>
          <div>
            <Box variant="awsui-key-label">Verified</Box>
            <Box variant="h1" margin={{ top: "xxs" }}>
              {busy ? "—" : verified}
            </Box>
            {!busy && accounts.length > 0 && (pending > 0 || error > 0) ? (
              <Box fontSize="body-s" color="text-body-secondary">
                {pending > 0 ? `${pending} pending verify` : ""}
                {pending > 0 && error > 0 ? " · " : ""}
                {error > 0 ? `${error} STS error` : ""}
              </Box>
            ) : null}
          </div>
          <div>
            <Box variant="awsui-key-label">Active scans</Box>
            <button
              type="button"
              className="mt-1 w-full max-w-full border-0 bg-transparent p-0 text-left disabled:cursor-not-allowed disabled:opacity-60"
              disabled={busy || inFlight === 0}
              onClick={openActiveModal}
              aria-label={
                inFlight > 0
                  ? `View ${inFlight} active scan${inFlight === 1 ? "" : "s"} across accounts`
                  : "No active scans"
              }
            >
              <Box variant="h1" margin={{ top: "n" }} className="dash-link">
                {busy ? "—" : inFlight}
              </Box>
              <Box fontSize="body-s" color="text-body-secondary">
                {busy
                  ? "—"
                  : inFlight > 0
                    ? "Queued or running — click the count to see accounts"
                    : "None queued or running right now"}
              </Box>
            </button>
          </div>
        </ColumnLayout>
      </Container>

      <Modal
        visible={activeModalOpen}
        onDismiss={() => setActiveModalOpen(false)}
        header="Accounts with active scans"
        size="medium"
        closeAriaLabel="Close"
        footer={
          <div className="flex w-full justify-end">
            <Button
              variant="primary"
              formAction="none"
              onClick={() => setActiveModalOpen(false)}
            >
              Close
            </Button>
          </div>
        }
      >
        <SpaceBetween size="m">
          <Box color="text-body-secondary" fontSize="body-s">
            Runs that are queued or running. Choose an AWS account ID to open the
            same page as that account&apos;s card.
          </Box>
          <SpaceBetween size="s">
            {activeScanAccountRows.map((row) => (
              <Box
                key={row.platformId}
                padding="s"
                className="rounded-[4px] border border-[var(--color-border-divider-default)]"
              >
                <SpaceBetween size="xs">
                  <Box fontSize="body-s" color="text-body-secondary">
                    {row.displayLabel}
                  </Box>
                  <Button
                    variant="inline-link"
                    formAction="none"
                    onClick={() => goToAccount(row.platformId)}
                  >
                    {row.awsAccountId}
                  </Button>
                  <Box fontSize="body-s" color="text-body-secondary">
                    {row.runLabels.join(" · ")}
                  </Box>
                </SpaceBetween>
              </Box>
            ))}
          </SpaceBetween>
        </SpaceBetween>
      </Modal>
    </>
  );
}
