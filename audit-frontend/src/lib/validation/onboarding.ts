import { z } from "zod";

export const awsAccountIdSchema = z
  .string()
  .trim()
  .regex(/^\d{12}$/, "Account ID must be exactly 12 digits.");

export const auditorRoleArnSchema = z
  .string()
  .trim()
  .min(1, "Role ARN is required.")
  .regex(
    /^arn:aws:iam::\d{12}:role\/[\w+=,.@/-]+$/,
    "Enter a valid IAM role ARN (arn:aws:iam::12-digit-account:role/name, optional path segments).",
  );

export const externalIdSchema = z
  .string()
  .trim()
  .min(1, "External ID is required for cross-account trust.");

export const registerAccountFormSchema = z.object({
  account_id: awsAccountIdSchema,
  role_arn: auditorRoleArnSchema,
  external_id: externalIdSchema,
});

export type RegisterAccountFormInput = z.infer<
  typeof registerAccountFormSchema
>;

export const accountRowUuidSchema = z
  .string()
  .trim()
  .regex(
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    "Enter a valid row UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).",
  );
