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
  .min(8, "External ID must be at least 8 characters (API requirement).");

function hasControlCharacter(s: string): boolean {
  for (let i = 0; i < s.length; i += 1) {
    const c = s.codePointAt(i);
    if (c !== undefined && c < 32) return true;
  }
  return false;
}

/** Free-form tag (prod, staging, UAT, …). Matched case-insensitively as a whole tag (prod ≠ production). */
export const environmentTagSchema = z
  .string()
  .trim()
  .min(1, "Environment tag is required.")
  .max(128, "Environment tag must be at most 128 characters.")
  .refine((s) => !hasControlCharacter(s), "Environment tag must not contain control characters.");

export const displayNameSchema = z
  .string()
  .trim()
  .min(1, "Account display name is required.")
  .max(255, "Account display name must be at most 255 characters.");

export const registerAccountFormSchema = z.object({
  account_id: awsAccountIdSchema,
  role_arn: auditorRoleArnSchema,
  external_id: externalIdSchema,
  display_name: displayNameSchema,
  /** Blank → stored as `other` on the server (same as leaving the tag unset). */
  environment: z.preprocess((val) => {
    if (typeof val !== "string") return val;
    const t = val.trim();
    return t === "" ? "other" : t;
  }, environmentTagSchema),
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
