"use client";

import Badge from "@cloudscape-design/components/badge";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import Container from "@cloudscape-design/components/container";
import Header from "@cloudscape-design/components/header";
import Table from "@cloudscape-design/components/table";
import type { Account } from "@/lib/types/dashboard";

function statusBadgeColor(status: string): "green" | "red" | "grey" {
  const s = status.toLowerCase();
  if (s === "verified") return "green";
  if (s === "error") return "red";
  return "grey";
}

export type DashboardAccountsTableProps = {
  accounts: Account[];
  accountScanBlocked: (platformAccountId: string) => boolean;
  startingAccountId: string | null;
  onStartRun: (platformAccountUuid: string) => void;
  loading?: boolean;
};

export function DashboardAccountsTable({
  accounts,
  accountScanBlocked,
  startingAccountId,
  onStartRun,
  loading = false,
}: Readonly<DashboardAccountsTableProps>) {
  return (
    <Container
      header={
        <Header
          variant="h2"
          description="Start an audit run for a verified account. Only one active run per account at a time."
        >
          Connected accounts
        </Header>
      }
    >
      <Table
        trackBy="id"
        variant="embedded"
        loading={loading}
        loadingText="Loading accounts"
        empty={
          <Box textAlign="center" color="text-body-secondary" padding="l">
            No accounts onboarded yet. Use <strong>Onboard AWS account</strong>{" "}
            in the side navigation.
          </Box>
        }
        columnDefinitions={[
          {
            id: "account",
            header: "AWS account ID",
            cell: (item) => (
              <Box variant="code" fontSize="body-s">
                {item.account_id}
              </Box>
            ),
          },
          {
            id: "status",
            header: "Status",
            cell: (item) => (
              <Badge color={statusBadgeColor(item.status)}>{item.status}</Badge>
            ),
            width: 140,
          },
          {
            id: "role",
            header: "Auditor role ARN",
            cell: (item) => (
              <Box
                fontSize="body-s"
                color="text-body-secondary"
                className="max-w-xl truncate"
              >
                {item.role_arn}
              </Box>
            ),
          },
          {
            id: "sts",
            header: "Verify",
            cell: (item) =>
              item.status === "error" && item.last_verify_error_code ? (
                <Box fontSize="body-s" color="text-status-error" variant="code">
                  STS: {item.last_verify_error_code}
                </Box>
              ) : (
                <Box color="text-body-secondary" fontSize="body-s">
                  —
                </Box>
              ),
            width: 200,
          },
          {
            id: "actions",
            header: "Actions",
            cell: (item) => {
              const busy = accountScanBlocked(item.id);
              const startingHere = startingAccountId === item.id;
              let label = "Start audit run";
              if (startingHere) label = "Starting…";
              else if (busy) label = "Run in progress";
              return (
                <div className="min-w-0 max-w-full">
                  <Button
                    variant="primary"
                    disabled={busy}
                    loading={startingHere}
                    wrapText={false}
                    onClick={() => onStartRun(item.id)}
                    nativeButtonAttributes={{
                      className:
                        "max-w-full whitespace-nowrap px-2 py-1 text-[11px] leading-tight sm:px-3 sm:text-xs md:text-sm",
                    }}
                  >
                    {label}
                  </Button>
                </div>
              );
            },
            width: 200,
          },
        ]}
        items={accounts}
      />
    </Container>
  );
}
