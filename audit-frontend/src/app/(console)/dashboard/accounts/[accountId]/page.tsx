"use client";

import Box from "@cloudscape-design/components/box";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import { useParams } from "next/navigation";

import { DashboardAccountAuditsClient } from "@/components/dashboard/DashboardAccountAuditsClient";
import { UUID_RE } from "@/lib/constants/dashboard";

export default function AccountAuditsPage() {
  const params = useParams();
  const raw =
    typeof params?.accountId === "string"
      ? params.accountId
      : Array.isArray(params?.accountId)
        ? params.accountId[0]
        : "";
  const accountId = raw?.trim() ?? "";

  if (!UUID_RE.test(accountId)) {
    return (
      <ContentLayout header={<Header variant="h1">Account</Header>}>
        <Box color="text-status-error" padding="l">
          Invalid account link — expected a platform row UUID
          (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
        </Box>
      </ContentLayout>
    );
  }

  return <DashboardAccountAuditsClient platformAccountId={accountId} />;
}
