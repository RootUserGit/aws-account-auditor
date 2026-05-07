"use client";

import Alert from "@cloudscape-design/components/alert";
import Box from "@cloudscape-design/components/box";
import BreadcrumbGroup from "@cloudscape-design/components/breadcrumb-group";
import Button from "@cloudscape-design/components/button";
import ContentLayout from "@cloudscape-design/components/content-layout";
import FormField from "@cloudscape-design/components/form-field";
import Header from "@cloudscape-design/components/header";
import Input from "@cloudscape-design/components/input";
import SpaceBetween from "@cloudscape-design/components/space-between";
import { useRouter } from "next/navigation";
import { useCallback, useState } from "react";

import { useApi } from "@/hooks";
import { isHttpOk } from "@/lib/api/http";
import { parseApiDetail } from "@/lib/helpers/parse-api-detail";
import { toast } from "@/lib/toast";
import {
  accountRowUuidSchema,
  registerAccountFormSchema,
} from "@/lib/validation/onboarding";

export default function OnboardingPage() {
  const api = useApi();
  const router = useRouter();
  const onBreadcrumbFollow = useCallback(
    (event: CustomEvent) => {
      event.preventDefault();
      const href = (event.detail as { href?: string }).href;
      if (href) router.push(href);
    },
    [router],
  );

  const [accountId, setAccountId] = useState("");
  const [roleArn, setRoleArn] = useState("");
  const [externalId, setExternalId] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  /** Platform row UUID for aws_accounts (e.g. ea501131-cc04-42aa-adb6-fcadc88df107) — not the 12-digit AWS account id */
  const [linkedRowId, setLinkedRowId] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<{
    account_id?: string;
    role_arn?: string;
    external_id?: string;
  }>({});

  async function register() {
    setMessage(null);
    const parsed = registerAccountFormSchema.safeParse({
      account_id: accountId,
      role_arn: roleArn,
      external_id: externalId,
    });
    if (!parsed.success) {
      const fe = parsed.error.flatten().fieldErrors;
      setFieldErrors({
        account_id: fe.account_id?.[0],
        role_arn: fe.role_arn?.[0],
        external_id: fe.external_id?.[0],
      });
      return;
    }
    setFieldErrors({});
    setLoading(true);
    try {
      const res = await api.registerAccount(parsed.data);
      const data = (res.data ?? {}) as Record<string, unknown>;
      if (!isHttpOk(res.status)) {
        const detail = data.detail;
        if (
          res.status === 409 &&
          detail &&
          typeof detail === "object" &&
          "existing_account_row_id" in detail
        ) {
          const rowId = String(
            (detail as { existing_account_row_id: string })
              .existing_account_row_id,
          );
          setLinkedRowId(rowId);
          setMessage(
            `${parseApiDetail(detail)} Use the UUID below for Verify/Delete, or delete the row first.`,
          );
          toast.error(parseApiDetail(detail));
          return;
        }
        const errMsg = parseApiDetail(detail);
        setMessage(errMsg);
        toast.error(errMsg);
        return;
      }
      const id = typeof data.id === "string" ? data.id : "";
      setLinkedRowId(id);
      setMessage(
        `Registered AWS account ${String(data.account_id ?? "")}. Saved row id (use for Verify): ${id}`,
      );
      toast.success("Account registered");
    } catch {
      setMessage("Network error — try again.");
      toast.error("Network error — try again.");
    } finally {
      setLoading(false);
    }
  }

  async function verify(accountUuid: string) {
    const trimmed = accountUuid.trim();
    const uuidParsed = accountRowUuidSchema.safeParse(trimmed);
    if (!uuidParsed.success) {
      setMessage(uuidParsed.error.issues[0]?.message ?? "Invalid row UUID.");
      return;
    }
    setLoading(true);
    setMessage(null);
    try {
      const res = await api.verifyAccount(trimmed);
      const data = (res.data ?? {}) as Record<string, unknown>;
      if (!isHttpOk(res.status)) {
        const errMsg = parseApiDetail(data.detail);
        setMessage(errMsg);
        toast.error(errMsg);
        return;
      }
      if (data.status === "verified") {
        setMessage("STS AssumeRole succeeded — account marked verified.");
        toast.success("Account verified");
        return;
      }
      if (data.status === "error") {
        const awsCode =
          typeof data.last_verify_error_code === "string"
            ? data.last_verify_error_code
            : "unknown";
        setMessage(
          [
            'HTTP 200 means the API ran; STS still failed — row status is "error".',
            `AWS error code: ${awsCode}`,
            "Typical fixes: trust policy must allow your platform IAM principal; ExternalId must match; role ARN must exist.",
          ].join("\n"),
        );
        return;
      }
      setMessage(`Account status after verify: ${String(data.status ?? "")}`);
    } catch {
      setMessage("Network error — try again.");
      toast.error("Network error — try again.");
    } finally {
      setLoading(false);
    }
  }

  async function removeAccount(accountUuid: string) {
    const trimmed = accountUuid.trim();
    const uuidParsed = accountRowUuidSchema.safeParse(trimmed);
    if (!uuidParsed.success) {
      setMessage(
        uuidParsed.error.issues[0]?.message ??
          "Enter a valid row UUID to delete.",
      );
      return;
    }
    setLoading(true);
    setMessage(null);
    try {
      const res = await api.deleteAccount(trimmed);
      if (res.status === 204) {
        setLinkedRowId(null);
        setMessage(
          "Account row deleted. You can Register again with the same AWS account ID.",
        );
        toast.success("Account deleted");
        return;
      }
      const data = (res.data ?? {}) as Record<string, unknown>;
      const errMsg = parseApiDetail(data.detail);
      setMessage(errMsg);
      toast.error(errMsg);
    } catch {
      setMessage("Network error — try again.");
      toast.error("Network error — try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <ContentLayout
      breadcrumbs={
        <BreadcrumbGroup
          items={[
            { text: "Welcome", href: "/" },
            { text: "Onboard AWS account", href: "/onboarding" },
          ]}
          onFollow={onBreadcrumbFollow}
        />
      }
      maxContentWidth={800}
      header={<Header variant="h1">Onboard AWS account</Header>}
    >
      <SpaceBetween size="l">
        <Box variant="p" color="text-body-secondary" fontSize="body-s">
          After <strong>Register</strong>, copy the <strong>row UUID</strong>{" "}
          (eight-dash format). Verify calls{" "}
          <Box variant="awsui-inline-code">
            POST /accounts/{"{uuid}"}/verify
          </Box>
          . Random strings with <Box variant="awsui-inline-code">/</Box> or{" "}
          <Box variant="awsui-inline-code">+</Box> are not valid UUIDs and will
          404.
        </Box>

        <SpaceBetween size="m">
          <FormField
            label="Account ID (12 digits)"
            errorText={fieldErrors.account_id}
          >
            <Input
              value={accountId}
              onChange={({ detail }) => {
                setAccountId(detail.value);
                setFieldErrors((e) => ({ ...e, account_id: undefined }));
              }}
              placeholder="123456789012"
            />
          </FormField>
          <FormField label="Auditor role ARN" errorText={fieldErrors.role_arn}>
            <Input
              value={roleArn}
              onChange={({ detail }) => {
                setRoleArn(detail.value);
                setFieldErrors((e) => ({ ...e, role_arn: undefined }));
              }}
              placeholder="arn:aws:iam::123456789012:role/YourAuditorRole"
            />
          </FormField>
          <FormField label="External ID" errorText={fieldErrors.external_id}>
            <Input
              value={externalId}
              onChange={({ detail }) => {
                setExternalId(detail.value);
                setFieldErrors((e) => ({ ...e, external_id: undefined }));
              }}
            />
          </FormField>
          <Button variant="primary" disabled={loading} onClick={register}>
            Register
          </Button>
          <QuickVerify
            key={linkedRowId ?? "no-row"}
            initialId={linkedRowId ?? ""}
            onVerify={verify}
            onDelete={removeAccount}
            disabled={loading}
          />
        </SpaceBetween>

        {message ? (
          <Alert type="info" header="Result">
            <Box variant="pre" fontSize="body-s">
              {message}
            </Box>
          </Alert>
        ) : null}
      </SpaceBetween>
    </ContentLayout>
  );
}

function QuickVerify({
  initialId,
  onVerify,
  onDelete,
  disabled,
}: Readonly<{
  initialId: string;
  onVerify: (id: string) => void;
  onDelete: (id: string) => void;
  disabled: boolean;
}>) {
  const [id, setId] = useState(initialId);

  return (
    <SpaceBetween size="m">
      <FormField
        label="Row UUID"
        description={
          <span>
            From API response field <Box variant="awsui-inline-code">id</Box>
          </span>
        }
      >
        <Input
          value={id}
          onChange={({ detail }) => setId(detail.value)}
          placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        />
      </FormField>
      <SpaceBetween direction="horizontal" size="xs">
        <Button disabled={disabled || !id.trim()} onClick={() => onVerify(id)}>
          Verify STS
        </Button>
        <Button
          variant="normal"
          disabled={disabled || !id.trim()}
          onClick={() => onDelete(id)}
        >
          Delete this row
        </Button>
      </SpaceBetween>
    </SpaceBetween>
  );
}
