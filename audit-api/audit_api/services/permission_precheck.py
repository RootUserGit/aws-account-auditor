"""AssumeRole + minimal read probes (limit-1 style) matching collectors before enqueueing a run."""

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError, ParamValidationError

from audit_data_collection.session import default_boto_config, session_from_credentials

# IAM action names that correspond to each probe (for end-user remediation; mirrors auditor policy).
IAM_ACTIONS_BY_CHECK_ID: dict[str, list[str]] = {
    "sts_assume_role": ["sts:AssumeRole"],
    "platform_credentials_missing": [],
    "sts_get_caller_identity": ["sts:GetCallerIdentity"],
    "iam_get_account_summary": ["iam:GetAccountSummary"],
    "ec2_describe_regions": ["ec2:DescribeRegions"],
    "s3_list_buckets": ["s3:ListAllMyBuckets"],
    "iam_list_users": ["iam:ListUsers"],
    "ec2_describe_security_groups": ["ec2:DescribeSecurityGroups"],
    "ec2_get_ebs_encryption_by_default": ["ec2:GetEbsEncryptionByDefault"],
    "ec2_describe_addresses": ["ec2:DescribeAddresses"],
    "ec2_describe_volumes": ["ec2:DescribeVolumes"],
    "ec2_describe_volumes_available": ["ec2:DescribeVolumes"],
    "ec2_describe_instances_stopped": ["ec2:DescribeInstances"],
    "rds_describe_db_instances": ["rds:DescribeDBInstances"],
    "ce_get_cost_and_usage": ["ce:GetCostAndUsage"],
    "kms_list_keys": ["kms:ListKeys"],
    "cloudtrail_describe_trails": ["cloudtrail:DescribeTrails"],
    "config_recorder_status": ["config:DescribeConfigurationRecorderStatus"],
    "iam_credential_report": ["iam:GenerateCredentialReport", "iam:GetCredentialReport"],
    "budgets_describe_budgets": ["budgets:DescribeBudgets", "budgets:ViewBudget"],
    "s3_get_account_public_access_block": ["s3:GetAccountPublicAccessBlock"],
    "s3_get_bucket_public_access_block": ["s3:GetBucketPublicAccessBlock"],
    "guardduty_list_and_get_detector": ["guardduty:ListDetectors", "guardduty:GetDetector"],
    "kms_describe_key_rotation": ["kms:DescribeKey", "kms:GetKeyRotationStatus"],
    "cloudtrail_get_trail_status": ["cloudtrail:GetTrailStatus"],
    "iam_user_mfa_and_policies": ["iam:ListMFADevices", "iam:ListAttachedUserPolicies"],
    "iam_get_account_password_policy": ["iam:GetAccountPasswordPolicy"],
    "securityhub_describe_hub": ["securityhub:DescribeHub"],
    "securityhub_get_findings": ["securityhub:GetFindings"],
    "support_describe_trusted_advisor_checks": ["support:DescribeTrustedAdvisorChecks"],
}


def _iam_actions_for(check_id: str) -> list[str]:
    return list(IAM_ACTIONS_BY_CHECK_ID.get(check_id, []))


def precheck_failure_http_detail(precheck: PrecheckOutcome) -> dict[str, Any]:
    """
    User-facing summary for HTTP 422 (no internal repo paths).
    """
    blocking = precheck.blocking
    if not blocking:
        return {
            "message": "Permission precheck reported a problem but no details were recorded.",
            "code": "PRECHECK_UNKNOWN",
            "blocking": [],
            "warnings": precheck.warnings,
        }
    first = blocking[0]
    fid = str(first.get("id", ""))

    if fid == "platform_credentials_missing":
        message = (
            "The audit API is not configured with AWS credentials, so it cannot call STS to assume your "
            "auditor role. Configure platform credentials for the API (see deployment documentation)."
        )
        code = "PLATFORM_CREDENTIALS_MISSING"
    elif fid == "sts_assume_role":
        message = (
            "AWS denied sts:AssumeRole for the auditor role ARN you registered. "
            "In the target account, fix the role trust policy and ExternalId so this platform can assume the role."
        )
        code = "ASSUME_ROLE_DENIED"
    elif fid == "sts_get_caller_identity":
        message = (
            "After assuming the auditor role, sts:GetCallerIdentity was denied. "
            "Grant sts:GetCallerIdentity on the assumed role session."
        )
        code = "STS_GET_CALLER_IDENTITY_DENIED"
    elif first.get("aws_error_code") in ("ParamValidationError", "InvalidParameterValue"):
        message = (
            "The permission precheck sent an invalid AWS API request (parameter validation). "
            "That is a platform bug, not missing IAM permissions on the auditor role."
        )
        code = "PRECHECK_INVALID_AWS_REQUEST"
    else:
        message = (
            "AWS denied a read-only API call required for this audit (see each item below). "
            "Attach the missing IAM actions to the auditor role in the scanned account, then retry."
        )
        code = "AUDITOR_READ_API_DENIED"

    return {
        "message": message,
        "code": code,
        "blocking": blocking,
        "warnings": precheck.warnings,
    }


def _precheck_boto_config() -> Config:
    """Faster failures than collectors; override with AWS_PRECHECK_* env vars."""
    connect = int(os.environ.get("AWS_PRECHECK_CONNECT_TIMEOUT", "5"))
    read = int(os.environ.get("AWS_PRECHECK_READ_TIMEOUT", "25"))
    return Config(
        connect_timeout=connect,
        read_timeout=read,
        retries={"max_attempts": 2, "mode": "standard"},
    )


def _client(session: Any, service_name: str, **kwargs: Any) -> Any:
    kwargs.setdefault("config", _precheck_boto_config())
    return session.client(service_name, **kwargs)


@dataclass
class PrecheckOutcome:
    """blocking = cannot run a meaningful audit; warnings = partial data / degraded collectors."""

    blocking: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[dict[str, Any]] = field(default_factory=list)


def _assume_auditor_session(role_arn: str, external_id: str) -> tuple[Any | None, dict[str, Any] | None]:
    try:
        sts = boto3.client("sts", config=default_boto_config())
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="audit-permission-precheck",
            ExternalId=external_id,
        )
        c = resp["Credentials"]
        creds = {
            "access_key_id": c["AccessKeyId"],
            "secret_access_key": c["SecretAccessKey"],
            "session_token": c["SessionToken"],
        }
        return session_from_credentials(creds), None
    except NoCredentialsError:
        return None, {
            "id": "platform_credentials_missing",
            "label": "Platform AWS credentials not configured",
            "required": True,
            "aws_error_code": "NoCredentialsError",
            "detail": "The audit API process has no AWS credentials (environment, profile, or instance role).",
            "iam_actions": _iam_actions_for("platform_credentials_missing"),
            "hint": (
                "Configure AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (or an instance/task role) for the API "
                "so it can call sts:AssumeRole into the customer auditor role."
            ),
        }
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "AssumeRoleFailed")
        msg = (e.response.get("Error", {}).get("Message") or "")[:2000]
        return None, {
            "id": "sts_assume_role",
            "label": "STS AssumeRole into the registered auditor role",
            "required": True,
            "aws_error_code": code,
            "detail": msg,
            "iam_actions": _iam_actions_for("sts_assume_role"),
            "resource": role_arn,
            "hint": (
                "This is not a missing permission on the auditor role's identity policy — the platform could not "
                "assume the role. In the account that owns the role, allow this platform's IAM principal in the "
                "role trust policy and match the ExternalId you entered when onboarding."
            ),
        }


def _entry(
    check_id: str,
    label: str,
    *,
    code: str,
    detail: str,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": check_id,
        "label": label,
        "required": True,
        "aws_error_code": code,
        "detail": detail[:2000],
        "iam_actions": _iam_actions_for(check_id),
    }
    return row


def _run_probe(
    check_id: str,
    label: str,
    fn: Callable[[], None],
    *,
    ignore_codes: frozenset[str] | None = None,
) -> dict[str, Any] | None:
    try:
        fn()
        return None
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        if ignore_codes and code in ignore_codes:
            return None
        msg = e.response.get("Error", {}).get("Message", "")[:2000]
        return _entry(check_id, label, code=code, detail=msg)
    except ParamValidationError as e:
        row = _entry(check_id, label, code="ParamValidationError", detail=str(e)[:2000])
        row["iam_actions"] = []
        row["hint"] = (
            "Invalid parameters were passed to the AWS SDK for this probe — fix the precheck code, "
            "not the customer IAM role."
        )
        return row
    except Exception as e:
        return _entry(check_id, label, code=type(e).__name__, detail=str(e)[:2000])


def _parallel_probes(
    specs: list[tuple[str, str, Callable[[], None]]],
    *,
    max_workers: int = 12,
) -> list[dict[str, Any]]:
    """Run independent probes in parallel; return list of error dicts (no None)."""
    if not specs:
        return []
    errors: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(_run_probe, cid, lab, fn) for cid, lab, fn in specs]
        for f in futures:
            err = f.result()
            if err:
                errors.append(err)
    return errors


def run_permission_precheck(role_arn: str, external_id: str) -> PrecheckOutcome:
    """
    Two-phase validation aligned with collectors in audit_data_collection (security + cost):

    1) Core IAM / EC2 regions / S3 bucket list — must pass or we return immediately (no long tail).
    2) Extended probes (limit-1 style in the session home region) — same APIs the worker uses for
       EC2 cost signals (volumes, instances, addresses), RDS, CE, KMS, etc. All blocking failures
       are returned together (parallel) so missing EC2 volume permissions surface before a scan.
    3) Optional warnings only if phases 1–2 pass — MFA depth, Security Hub subscription, Support plan.
    """
    out = PrecheckOutcome()
    session, assume_block = _assume_auditor_session(role_arn, external_id)
    if session is None:
        if assume_block:
            out.blocking.append(assume_block)
        else:
            out.blocking.append(
                {
                    "id": "sts_assume_role",
                    "label": "STS AssumeRole into the registered auditor role",
                    "required": True,
                    "aws_error_code": "Unknown",
                    "detail": "Assume role failed with no error details.",
                    "iam_actions": _iam_actions_for("sts_assume_role"),
                }
            )
        return out

    sts_c = _client(session, "sts")
    account_id = ""
    try:
        ident = sts_c.get_caller_identity()
        account_id = ident.get("Account") or ""
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        msg = (e.response.get("Error", {}).get("Message") or "")[:2000]
        out.blocking.append(
            {
                "id": "sts_get_caller_identity",
                "label": "STS GetCallerIdentity",
                "required": True,
                "aws_error_code": code,
                "detail": msg or "Needed to resolve account id for scoped APIs.",
                "iam_actions": _iam_actions_for("sts_get_caller_identity"),
            }
        )
        return out

    home = session.region_name or "us-east-1"
    iam = _client(session, "iam")
    s3 = _client(session, "s3")
    ec2_home = _client(session, "ec2", region_name=home)

    # --- Phase 1: core gate (parallel, fast-fail after this phase if anything fails)
    phase1: list[tuple[str, str, Callable[[], None]]] = [
        ("iam_get_account_summary", "IAM GetAccountSummary", lambda: iam.get_account_summary()),
        (
            "ec2_describe_regions",
            "EC2 DescribeRegions",
            lambda: _client(session, "ec2", region_name=home).describe_regions(),
        ),
        ("s3_list_buckets", "S3 ListAllMyBuckets", lambda: s3.list_buckets()),
    ]
    out.blocking.extend(_parallel_probes(phase1))
    if out.blocking:
        return out

    # Bucket sample for per-bucket APIs (match S3 PAB collector)
    first_bucket: str | None = None
    try:
        lb = s3.list_buckets()
        names = [b["Name"] for b in lb.get("Buckets", [])]
        if names:
            first_bucket = names[0]
    except ClientError:
        pass

    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=30)

    # --- Phase 2: extended required — every API path used by security/cost collectors (sampled home region)
    phase2: list[tuple[str, str, Callable[[], None]]] = [
        ("iam_list_users", "IAM ListUsers (sample)", lambda: iam.list_users(MaxItems=1)),
        (
            "ec2_describe_security_groups",
            "EC2 DescribeSecurityGroups (sample)",
            lambda: ec2_home.describe_security_groups(MaxResults=5),
        ),
        (
            "ec2_get_ebs_encryption_by_default",
            "EC2 GetEbsEncryptionByDefault",
            lambda: ec2_home.get_ebs_encryption_by_default(),
        ),
        (
            "ec2_describe_addresses",
            "EC2 DescribeAddresses (EIP / cost signals)",
            # DescribeAddresses has no MaxResults (unlike DescribeVolumes); matches cost collector.
            lambda: ec2_home.describe_addresses(),
        ),
        (
            "ec2_describe_volumes",
            "EC2 DescribeVolumes (unattached EBS / cost signals)",
            lambda: ec2_home.describe_volumes(MaxResults=5),
        ),
        (
            "ec2_describe_volumes_available",
            "EC2 DescribeVolumes (status=available, unused volumes)",
            lambda: ec2_home.describe_volumes(
                Filters=[{"Name": "status", "Values": ["available"]}],
                MaxResults=5,
            ),
        ),
        (
            "ec2_describe_instances_stopped",
            "EC2 DescribeInstances (stopped — cost signals)",
            lambda: ec2_home.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}],
                MaxResults=5,
            ),
        ),
        (
            "rds_describe_db_instances",
            "RDS DescribeDBInstances",
            # MaxRecords, if set, must be 20–100 per RDS API; omit to mirror security collector.
            lambda: _client(session, "rds", region_name=home).describe_db_instances(),
        ),
        (
            "ce_get_cost_and_usage",
            "Cost Explorer GetCostAndUsage",
            lambda: _client(session, "ce", region_name="us-east-1").get_cost_and_usage(
                TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            ),
        ),
        (
            "kms_list_keys",
            "KMS ListKeys",
            lambda: _client(session, "kms", region_name=home).list_keys(Limit=5),
        ),
        (
            "cloudtrail_describe_trails",
            "CloudTrail DescribeTrails",
            lambda: _client(session, "cloudtrail").describe_trails(),
        ),
        (
            "config_recorder_status",
            "Config DescribeConfigurationRecorderStatus",
            lambda: _client(session, "config").describe_configuration_recorder_status(),
        ),
        (
            "iam_credential_report",
            "IAM credential report (GenerateCredentialReport + GetCredentialReport)",
            lambda: _credential_report_probe(iam),
        ),
    ]

    if account_id:

        def _s3_account_pab() -> None:
            try:
                _client(session, "s3control").get_public_access_block(AccountId=account_id)
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") == "NoSuchPublicAccessBlockConfiguration":
                    return
                raise

        bud = _client(session, "budgets")
        phase2.append(
            (
                "budgets_describe_budgets",
                "Budgets DescribeBudgets",
                lambda: bud.describe_budgets(AccountId=account_id, MaxResults=5),
            )
        )
        phase2.append(
            (
                "s3_get_account_public_access_block",
                "S3 Control GetAccountPublicAccessBlock",
                _s3_account_pab,
            )
        )

    if first_bucket:
        bn = first_bucket

        def _s3_bucket_pab() -> None:
            try:
                s3.get_public_access_block(Bucket=bn)
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") in (
                    "NoSuchPublicAccessBlockConfiguration",
                    "NoSuchBucket",
                ):
                    return
                raise

        phase2.append(
            (
                "s3_get_bucket_public_access_block",
                "S3 GetBucketPublicAccessBlock",
                _s3_bucket_pab,
            )
        )

    # GuardDuty: list + get when a detector exists (collector path)
    def _guardduty_probe() -> None:
        gd = _client(session, "guardduty", region_name=home)
        ids = gd.list_detectors(MaxResults=10).get("DetectorIds") or []
        if ids:
            gd.get_detector(DetectorId=ids[0])

    phase2.append(("guardduty_list_and_get_detector", "GuardDuty ListDetectors + GetDetector", _guardduty_probe))

    # KMS: list + describe_key on first key (collector path)
    def _kms_depth_probe() -> None:
        kms = _client(session, "kms", region_name=home)
        keys = kms.list_keys(Limit=5).get("Keys") or []
        if not keys:
            return
        kid = keys[0].get("KeyId")
        if not kid:
            return
        meta = kms.describe_key(KeyId=kid)["KeyMetadata"]
        if meta.get("KeyManager") == "CUSTOMER" and meta.get("KeyState") == "Enabled":
            try:
                kms.get_key_rotation_status(KeyId=kid)
            except ClientError:
                pass

    phase2.append(("kms_describe_key_rotation", "KMS DescribeKey + GetKeyRotationStatus (sample key)", _kms_depth_probe))

    # CloudTrail: GetTrailStatus when a trail exists
    def _cloudtrail_status_probe() -> None:
        ct = _client(session, "cloudtrail")
        trails = ct.describe_trails().get("trailList") or []
        if not trails:
            return
        arn = trails[0].get("TrailARN")
        if arn:
            ct.get_trail_status(Name=arn)

    phase2.append(("cloudtrail_get_trail_status", "CloudTrail GetTrailStatus (sample trail)", _cloudtrail_status_probe))

    # IAM: MFA + attached policies on first user (collector path)
    def _iam_user_depth_probe() -> None:
        lu = iam.list_users(MaxItems=5)
        users = lu.get("Users") or []
        if not users:
            return
        uname = users[0].get("UserName")
        if not uname:
            return
        iam.list_mfa_devices(UserName=uname)
        iam.list_attached_user_policies(UserName=uname, MaxItems=5)

    phase2.append(("iam_user_mfa_and_policies", "IAM ListMFADevices + ListAttachedUserPolicies (sample user)", _iam_user_depth_probe))

    out.blocking.extend(_parallel_probes(phase2))
    if out.blocking:
        return out

    # --- Phase 3: optional / degraded only when core + extended passed
    def add_warn(entry: dict[str, Any]) -> None:
        entry.setdefault("required", False)
        out.warnings.append(entry)

    def try_warn(check_id: str, label: str, fn: Callable[[], None], *, ignore_codes: frozenset[str] | None = None) -> None:
        err = _run_probe(check_id, label, fn, ignore_codes=ignore_codes)
        if err:
            err["required"] = False
            add_warn(err)

    try_warn(
        "iam_get_account_password_policy",
        "IAM GetAccountPasswordPolicy",
        lambda: iam.get_account_password_policy(),
        ignore_codes=frozenset({"NoSuchEntity"}),
    )

    try_warn(
        "securityhub_describe_hub",
        "Security Hub DescribeHub",
        lambda: _client(session, "securityhub", region_name=home).describe_hub(),
        ignore_codes=frozenset(
            {
                "InvalidAccessException",
                "AccessDeniedException",
                "SubscriptionRequiredException",
            }
        ),
    )

    try_warn(
        "securityhub_get_findings",
        "Security Hub GetFindings (sample)",
        lambda: _client(session, "securityhub", region_name=home).get_findings(
            MaxResults=5,
            Filters={"WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}]},
        ),
        ignore_codes=frozenset(
            {
                "InvalidAccessException",
                "AccessDeniedException",
                "SubscriptionRequiredException",
            }
        ),
    )

    try_warn(
        "support_describe_trusted_advisor_checks",
        "Support DescribeTrustedAdvisorChecks",
        lambda: _client(session, "support", region_name="us-east-1").describe_trusted_advisor_checks(language="en"),
        ignore_codes=frozenset(
            {
                "SubscriptionRequiredException",
                "AccessDeniedException",
            }
        ),
    )

    return out


def _credential_report_probe(iam: Any) -> None:
    iam.generate_credential_report()
    for _ in range(12):
        try:
            iam.get_credential_report()
            return
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ReportInProgressException":
                time.sleep(0.5)
                continue
            raise
