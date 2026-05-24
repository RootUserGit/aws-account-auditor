# Customer auditor IAM role

1. Create an IAM role in the **customer account** trusted by your **platform principal** (another AWS account’s role/user or SAML/OIDC).
2. Attach an inline policy or customer-managed policy using **`auditor-policy.json`** as a baseline. Tighten further per your compliance needs.
3. Require **`sts:ExternalId`** in the trust policy condition matching the value stored in this platform for the linked AWS account.
4. Never grant `iam:PassRole`, `*:*` write actions, or data-plane destructive permissions for auditing.

Example trust policy skeleton (replace placeholders):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::PLATFORM_ACCOUNT_ID:root" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": { "sts:ExternalId": "YOUR_EXTERNAL_ID_FROM_APP" }
      }
    }
  ]
}
```

Trusted Advisor and Security Hub APIs may return access denied in accounts without the required subscription or service enablement — the collectors record partial success.

AUD-001 expansion (S3 logging / policy status, IAM policy analysis, RDS extended posture, CloudTrail→CloudWatch Logs, ELBv2, Flow Logs, DynamoDB PITR, ElastiCache, EFS, etc.) requires the additional **read-only** actions listed in `auditor-policy.json` (see the `AuditReadOnlyDiscovery` statement). Update customer roles when you ship this pack.
