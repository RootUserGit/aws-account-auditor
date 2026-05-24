"use client";

import Badge from "@cloudscape-design/components/badge";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import Container from "@cloudscape-design/components/container";
import FormField from "@cloudscape-design/components/form-field";
import Header from "@cloudscape-design/components/header";
import Input from "@cloudscape-design/components/input";
import Select from "@cloudscape-design/components/select";
import type { SelectProps } from "@cloudscape-design/components/select";
import SpaceBetween from "@cloudscape-design/components/space-between";
import { useCallback, useMemo, useState } from "react";

import { toast } from "@/lib/toast";
import type { Account } from "@/lib/types/dashboard";
import {
  DASHBOARD_ENVIRONMENT_FILTER_ALL,
  accountMatchesEnvironmentSelect,
  environmentBadgeLabel,
  userEnvironmentSelectOptionsFromAccounts,
} from "@/lib/utils/dashboard-environment";

type SelectOption = NonNullable<SelectProps["selectedOption"]>;

function statusBadgeColor(status: string): "green" | "red" | "grey" {
  const s = status.toLowerCase();
  if (s === "verified") return "green";
  if (s === "error") return "red";
  return "grey";
}

export type DashboardAccountsCardsProps = {
  accounts: Account[];
  accountScanBlocked: (platformAccountId: string) => boolean;
  loading?: boolean;
  onOpenAccount: (platformAccountUuid: string) => void;
};

const ALL_OPTION: SelectOption = {
  label: "All",
  value: DASHBOARD_ENVIRONMENT_FILTER_ALL,
};

export function DashboardAccountsCards({
  accounts,
  accountScanBlocked,
  loading = false,
  onOpenAccount,
}: Readonly<DashboardAccountsCardsProps>) {
  const [search, setSearch] = useState("");
  const [environmentOption, setEnvironmentOption] =
    useState<SelectOption | null>(ALL_OPTION);

  const envSelectOptions = useMemo(
    () => userEnvironmentSelectOptionsFromAccounts(accounts),
    [accounts],
  );

  const effectiveEnvValue = useMemo(() => {
    const v = environmentOption?.value;
    if (!v || v === DASHBOARD_ENVIRONMENT_FILTER_ALL) {
      return DASHBOARD_ENVIRONMENT_FILTER_ALL;
    }
    if (!envSelectOptions.some((o) => o.value === v)) {
      return DASHBOARD_ENVIRONMENT_FILTER_ALL;
    }
    return v;
  }, [environmentOption, envSelectOptions]);

  const selectedOptionForSelect = useMemo((): SelectOption | null => {
    if (effectiveEnvValue === DASHBOARD_ENVIRONMENT_FILTER_ALL) {
      return ALL_OPTION;
    }
    return (
      envSelectOptions.find((o) => o.value === effectiveEnvValue) ?? ALL_OPTION
    );
  }, [effectiveEnvValue, envSelectOptions]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return accounts.filter((a) => {
      if (!accountMatchesEnvironmentSelect(a, effectiveEnvValue)) return false;
      if (!q) return true;
      const name = (a.display_name ?? "").toLowerCase();
      const id = a.account_id.toLowerCase();
      const env = a.environment.trim().toLowerCase();
      return name.includes(q) || id.includes(q) || env.includes(q);
    });
  }, [accounts, search, effectiveEnvValue]);

  const copyRoleArn = useCallback(async (arn: string) => {
    try {
      await navigator.clipboard.writeText(arn);
      toast.success("Role ARN copied");
    } catch {
      toast.error("Could not copy to clipboard");
    }
  }, []);

  const emptyMessage =
    accounts.length === 0 ? (
      <Box textAlign="center" color="text-body-secondary" padding="l">
        No accounts onboarded yet. Use <strong>Onboard AWS account</strong> in
        the side navigation.
      </Box>
    ) : (
      <Box textAlign="center" color="text-body-secondary" padding="l">
        No accounts match your search or environment filter. Choose{" "}
        <strong>All</strong> or another tag to see more accounts.
      </Box>
    );

  return (
    <Container
      header={
        <Header
          variant="h2"
          description="Environment filter lists tags used on accounts (not the default “other”). Search matches name, account ID, or tag text. Click a card or Open account for scans and findings."
        >
          Connected accounts
        </Header>
      }
    >
      <SpaceBetween size="l">
        <div className="flex w-full min-w-0 flex-col gap-4 lg:flex-row lg:items-end lg:gap-6">
          <div className="min-w-0 w-full flex-1 lg:max-w-xl">
            <FormField label="Search" stretch>
              <Input
                value={search}
                disabled={loading}
                onChange={({ detail }) => setSearch(detail.value)}
                placeholder="Name, 12-digit account ID, or tag text"
                type="search"
              />
            </FormField>
          </div>
          <div className="min-w-0 w-full flex-1 lg:max-w-md">
            <FormField
              label="Environment tag"
              description="All shows every account. Other values are tags someone set at onboarding (default tag is hidden here)."
              stretch
            >
              <Select
                disabled={loading}
                filteringType="manual"
                options={envSelectOptions}
                selectedAriaLabel="Selected environment"
                selectedOption={selectedOptionForSelect}
                onChange={({ detail }) =>
                  setEnvironmentOption(detail.selectedOption ?? ALL_OPTION)
                }
                placeholder="All"
              />
            </FormField>
          </div>
        </div>

        {loading ? (
          <Box color="text-body-secondary" fontSize="body-s">
            Loading accounts…
          </Box>
        ) : filtered.length === 0 ? (
          emptyMessage
        ) : (
          <div className="grid w-full min-w-0 grid-cols-1 gap-4 md:grid-cols-2 2xl:grid-cols-3">
            {filtered.map((item) => {
              const busy = accountScanBlocked(item.id);
              const envBadge = environmentBadgeLabel(item.environment);

              return (
                <div
                  key={item.id}
                  role="button"
                  tabIndex={0}
                  className="w-full min-w-0 cursor-pointer rounded-[var(--border-radius-container)] border border-[var(--color-border-divider-default)] bg-[var(--color-background-container-content)] p-4 text-left shadow-sm transition hover:border-[var(--color-border-control-default)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2"
                  onClick={() => onOpenAccount(item.id)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      onOpenAccount(item.id);
                    }
                  }}
                  aria-label={`Open account ${item.display_name}`}
                >
                  <SpaceBetween size="m">
                    <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-start sm:justify-between">
                      <Box
                        variant="h3"
                        margin={{ bottom: "n" }}
                        className="min-w-0 break-words pr-0 sm:pr-2"
                      >
                        {item.display_name}
                      </Box>
                      <SpaceBetween
                        direction="horizontal"
                        size="xs"
                        className="shrink-0 flex-wrap"
                      >
                        <Badge color="grey">{envBadge}</Badge>
                        <Badge color={statusBadgeColor(item.status)}>
                          {item.status}
                        </Badge>
                      </SpaceBetween>
                    </div>

                    <div className="min-w-0">
                      <Box
                        fontSize="body-s"
                        color="text-body-secondary"
                        margin={{ bottom: "xxs" }}
                      >
                        AWS account ID
                      </Box>
                      <Box variant="code" fontSize="body-s" className="break-all">
                        {item.account_id}
                      </Box>
                    </div>

                    <div className="min-w-0">
                      <Box
                        fontSize="body-s"
                        color="text-body-secondary"
                        margin={{ bottom: "xxs" }}
                      >
                        Auditor role ARN
                      </Box>
                      <div
                        className="pointer-events-none break-all line-clamp-3 text-[length:var(--font-body-s-size)] text-[var(--color-text-body-secondary)] sm:line-clamp-2"
                        title={item.role_arn}
                      >
                        {item.role_arn}
                      </div>
                    </div>

                    {item.status === "error" &&
                    item.last_verify_error_code ? (
                      <Box
                        fontSize="body-s"
                        color="text-status-error"
                        variant="code"
                        className="break-words"
                      >
                        STS: {item.last_verify_error_code}
                      </Box>
                    ) : null}

                    <div
                      className="flex min-w-0 flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center sm:gap-3"
                      onClick={(e) => e.stopPropagation()}
                      onKeyDown={(e) => e.stopPropagation()}
                    >
                      <Button
                        variant="inline-link"
                        formAction="none"
                        onClick={() => void copyRoleArn(item.role_arn)}
                      >
                        Copy role ARN
                      </Button>
                      <Button
                        variant="primary"
                        formAction="none"
                        disabled={busy}
                        onClick={() => onOpenAccount(item.id)}
                      >
                        {busy ? "Run in progress" : "Open account"}
                      </Button>
                    </div>
                  </SpaceBetween>
                </div>
              );
            })}
          </div>
        )}
      </SpaceBetween>
    </Container>
  );
}
