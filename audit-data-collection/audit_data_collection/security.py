from __future__ import annotations

from typing import Any

import boto3
from botocore.exceptions import ClientError

from audit_data_collection.types import CollectorResult


def collect_security(session: boto3.Session, account_id: str) -> CollectorResult:
    """Gather security-relevant read-only signals (best-effort per API)."""
    out = CollectorResult(bundle={})

    # IAM account summary
    try:
        iam = session.client("iam")
        out.bundle["iam_summary"] = iam.get_account_summary()["SummaryMap"]
    except ClientError as e:
        out.merge_errors("iam.get_account_summary", e)

    try:
        iam = session.client("iam")
        out.bundle["iam_password_policy"] = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError:
        out.bundle["iam_password_policy"] = None

    # IAM credential report (optional)
    try:
        iam = session.client("iam")
        iam.generate_credential_report()
        report = iam.get_credential_report()["Content"].decode("utf-8")
        out.bundle["iam_credential_report_csv"] = report[:50000]  # cap size
    except ClientError:
        out.bundle["iam_credential_report_csv"] = None

    # Users without MFA (console users) — include metadata for reporting / UI
    try:
        iam = session.client("iam")
        users: list[dict[str, Any]] = []
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page.get("Users", []):
                users.append(
                    {
                        "user_name": u["UserName"],
                        "arn": u.get("Arn", ""),
                        "create_date": u.get("CreateDate"),
                        "password_last_used": u.get("PasswordLastUsed"),
                    }
                )
        without_mfa: list[dict[str, Any]] = []
        for row in users[:200]:
            username = row["user_name"]
            try:
                mfas = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                if not mfas:
                    without_mfa.append(row)
            except ClientError:
                without_mfa.append(row)
        out.bundle["iam_users_without_mfa"] = without_mfa
        out.bundle["iam_user_count"] = len(users)
    except ClientError as e:
        out.merge_errors("iam.users_mfa", e)

    # S3 buckets + public access blocks
    try:
        s3 = session.client("s3")
        buckets_resp = s3.list_buckets()
        buckets = [b["Name"] for b in buckets_resp.get("Buckets", [])]
        bucket_pab = []
        for name in buckets[:100]:
            row: dict[str, Any] = {"name": name}
            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                row["public_access_block"] = pab
            except ClientError as ce:
                row["public_access_block_error"] = ce.response.get("Error", {}).get("Code")
            bucket_pab.append(row)
        out.bundle["s3_buckets"] = bucket_pab
    except ClientError as e:
        out.merge_errors("s3.list_buckets", e)

    # Account-level public access block (S3 Control)
    try:
        s3ctl = session.client("s3control")
        r = s3ctl.get_public_access_block(AccountId=account_id)
        out.bundle["s3_account_public_access_block"] = r.get("PublicAccessBlockConfiguration")
    except ClientError as e:
        out.bundle["s3_account_public_access_block"] = None
        code = e.response.get("Error", {}).get("Code", "")
        if code not in ("NoSuchPublicAccessBlockConfiguration", "AccessDenied"):
            out.merge_errors("s3control.get_public_access_block", e)

    # EC2 default security groups (sample regions)
    try:
        ec2r = session.client("ec2", region_name=session.region_name or "us-east-1")
        regions = [r["RegionName"] for r in ec2r.describe_regions()["Regions"]][:8]
        default_sgs: list[dict[str, Any]] = []
        for region in regions:
            try:
                ec2 = session.client("ec2", region_name=region)
                for sg in ec2.describe_security_groups(
                    Filters=[{"Name": "group-name", "Values": ["default"]}]
                ).get("SecurityGroups", []):
                    open_world = False
                    for perm in sg.get("IpPermissions", []):
                        for rng in perm.get("IpRanges", []):
                            if rng.get("CidrIp") in ("0.0.0.0/0", "::/0"):
                                open_world = True
                    default_sgs.append(
                        {
                            "region": region,
                            "group_id": sg["GroupId"],
                            "vpc_id": sg.get("VpcId"),
                            "ingress_count": len(sg.get("IpPermissions", [])),
                            "egress_count": len(sg.get("IpPermissionsEgress", [])),
                            "open_to_world": open_world,
                        }
                    )
            except ClientError:
                continue
        out.bundle["ec2_default_security_groups"] = default_sgs
    except ClientError as e:
        out.merge_errors("ec2.regions", e)

    # AWS Config — optional
    try:
        cfg = session.client("config")
        status = cfg.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
        out.bundle["config_recorders"] = status
    except ClientError:
        out.bundle["config_recorders"] = None

    # Security Hub — optional
    try:
        sh = session.client("securityhub")
        out.bundle["security_hub_enabled"] = True
        findings = sh.get_findings(MaxResults=10, Filters={"WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}]})
        out.bundle["security_hub_sample_finding_count"] = len(findings.get("Findings", []))
    except ClientError:
        out.bundle["security_hub_enabled"] = False

    # CloudTrail trails (metadata)
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails()["trailList"]
        out.bundle["cloudtrail_trails"] = [
            {
                "name": t.get("Name"),
                "is_multi_region": t.get("IsMultiRegionTrail"),
                "is_logging": None,
            }
            for t in trails[:20]
        ]
        for i, t in enumerate(ct.describe_trails()["trailList"][:5]):
            try:
                status = ct.get_trail_status(Name=t["TrailARN"])
                if i < len(out.bundle["cloudtrail_trails"]):
                    out.bundle["cloudtrail_trails"][i]["is_logging"] = status.get("IsLogging")
            except ClientError:
                pass
    except ClientError as e:
        out.bundle["cloudtrail_trails"] = []
        out.merge_errors("cloudtrail", e)

    return out


def merge_security_bundle(result: CollectorResult) -> dict[str, Any]:
    """Flatten for rule engine consumption."""
    base = dict(result.bundle)
    base["_collector_errors"] = result.errors
    return base
