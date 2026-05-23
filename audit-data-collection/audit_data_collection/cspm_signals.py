"""Trend-style CSPM signals for AUD-001: derived checks from merged collector bundles.

Each key is referenced by rule YAML (`cspm_signal: KEY`). Values are dicts:
  status: passed | failed | unknown
  evidence: JSON-serializable dict
  remediation_hint: optional str
  resource_id: optional str
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _days_since_dt(value: Any) -> int | None:
    if value is None:
        return None
    dt: datetime | None = None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str) and value.strip():
        try:
            s = value.strip().replace("Z", "+00:00")
            dt = datetime.fromisoformat(s)
        except ValueError:
            return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0, int((datetime.now(timezone.utc) - dt).total_seconds() / 86400))


def _sig(
    status: str,
    evidence: dict[str, Any] | None = None,
    *,
    remediation: str = "",
    resource_id: str | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "evidence": evidence or {},
        "remediation_hint": remediation,
        "resource_id": resource_id,
    }


def _errors_text(bundle: dict[str, Any], collector_errors: list[Any] | None) -> str:
    parts: list[str] = []
    for e in collector_errors or []:
        parts.append(str(e))
    for e in bundle.get("_collector_errors") or []:
        parts.append(str(e))
    for e in bundle.get("_errors") or []:
        parts.append(str(e))
    return " ".join(parts).lower()


def _policy_doc_has_star_action(doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list):
        return False
    for st in stmts:
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        act = st.get("Action")
        if act == "*":
            return True
        if isinstance(act, list) and "*" in act:
            return True
        if isinstance(act, str) and act.strip() == "*":
            return True
    return False


def build_cspm_signals(bundle: dict[str, Any], *, collector_errors: list[Any] | None = None) -> dict[str, Any]:
    """Build all CSPM signal keys consumed by `cspm_signal` rules (AUD-001)."""
    b = bundle
    err_txt = _errors_text(b, collector_errors)
    signals: dict[str, dict[str, Any]] = {}

    # --- IAM credential report ---
    csv = b.get("iam_credential_report_csv")
    if not csv:
        st = "unknown" if "credential" in err_txt or "accessdenied" in err_txt else "failed"
        signals["IAM_CREDENTIAL_REPORT_MISSING"] = _sig(
            st,
            {"detail": "no_credential_report"},
            remediation="Allow iam:GenerateCredentialReport and iam:GetCredentialReport for the auditor role.",
        )
    else:
        signals["IAM_CREDENTIAL_REPORT_MISSING"] = _sig("passed", {"bytes": len(csv)})

    stale_console: list[dict[str, Any]] = []
    if csv:
        import csv as _csv
        import io as _io

        rdr = _csv.DictReader(_io.StringIO(csv))
        for row in rdr:
            if row.get("user") == "<root_account>":
                continue
            if row.get("password_enabled") != "true":
                continue
            plu = (row.get("password_last_used") or "").strip()
            if plu in ("N/A", "no_information", ""):
                continue
            try:
                age = _days_since_dt(plu)
            except Exception:
                age = None
            if age is not None and age >= 90:
                stale_console.append({"user_name": row.get("user"), "password_last_used": plu, "age_days": age})
    if not csv:
        signals["IAM_STALE_CONSOLE_PASSWORD_90D"] = _sig("unknown", {}, remediation="Credential report unavailable.")
    elif stale_console:
        signals["IAM_STALE_CONSOLE_PASSWORD_90D"] = _sig(
            "failed",
            {"users": stale_console[:40], "count": len(stale_console)},
            remediation="Reset passwords or disable unused console profiles for IAM users inactive 90+ days.",
        )
    else:
        signals["IAM_STALE_CONSOLE_PASSWORD_90D"] = _sig("passed", {"users_flagged": 0})

    inline_rows = b.get("iam_users_inline_policies") or []
    if inline_rows is None:
        signals["IAM_USER_INLINE_POLICIES_PRESENT"] = _sig("unknown", {}, remediation="IAM inline policy inventory not collected.")
    elif inline_rows:
        signals["IAM_USER_INLINE_POLICIES_PRESENT"] = _sig(
            "failed",
            {"users": inline_rows[:35]},
            remediation="Replace inline policies with customer-managed IAM policies for reviewability and reuse.",
        )
    else:
        signals["IAM_USER_INLINE_POLICIES_PRESENT"] = _sig("passed", {"users_with_inline": 0})

    wild_inline = b.get("iam_inline_policy_wildcard_hits") or []
    if wild_inline is None:
        signals["IAM_INLINE_POLICY_WILDCARD_ACTION"] = _sig("unknown", {}, remediation="Inline policy documents were not analyzed.")
    elif wild_inline:
        signals["IAM_INLINE_POLICY_WILDCARD_ACTION"] = _sig(
            "failed",
            {"policies": wild_inline[:30]},
            remediation="Remove Action: * (or \"*\") from inline policies; scope to specific API operations.",
        )
    else:
        signals["IAM_INLINE_POLICY_WILDCARD_ACTION"] = _sig("passed", {"wildcard_inline_hits": 0})

    wild_att = b.get("iam_attached_policy_wildcard_hits") or []
    if wild_att is None:
        signals["IAM_ATTACHED_CUSTOMER_POLICY_WILDCARD_ACTION"] = _sig(
            "unknown", {}, remediation="Attached customer-managed policy documents were not analyzed."
        )
    elif wild_att:
        signals["IAM_ATTACHED_CUSTOMER_POLICY_WILDCARD_ACTION"] = _sig(
            "failed",
            {"policies": wild_att[:25]},
            remediation="Replace overly broad customer-managed policies; avoid Action * with Resource *.",
        )
    else:
        signals["IAM_ATTACHED_CUSTOMER_POLICY_WILDCARD_ACTION"] = _sig("passed", {"wildcard_attached_hits": 0})

    # --- S3 ---
    buckets = b.get("s3_buckets") or []
    if not buckets and b.get("s3_buckets") is not None:
        signals["S3_BUCKET_SERVER_ACCESS_LOGGING_DISABLED"] = _sig("passed", {"buckets": 0})
    elif not buckets:
        signals["S3_BUCKET_SERVER_ACCESS_LOGGING_DISABLED"] = _sig("unknown", {}, remediation="No S3 bucket inventory.")
    else:
        missing_log = [x for x in buckets if not x.get("server_access_logging_enabled")]
        if missing_log:
            signals["S3_BUCKET_SERVER_ACCESS_LOGGING_DISABLED"] = _sig(
                "failed",
                {"buckets_missing_logging": [x.get("name") for x in missing_log[:35]], "sample_detail": missing_log[:12]},
                remediation="Enable S3 server access logging to a dedicated logging bucket with least-privilege ACL/bucket policy.",
            )
        else:
            signals["S3_BUCKET_SERVER_ACCESS_LOGGING_DISABLED"] = _sig("passed", {"buckets_checked": len(buckets)})

    no_enc = [x for x in buckets if x.get("default_encryption_enabled") is False] if buckets else []
    if buckets is None or (not buckets and b.get("s3_buckets") is None):
        signals["S3_DEFAULT_ENCRYPTION_DISABLED_ANY_BUCKET"] = _sig("unknown", {}, remediation="S3 bucket encryption not evaluated.")
    elif no_enc:
        signals["S3_DEFAULT_ENCRYPTION_DISABLED_ANY_BUCKET"] = _sig(
            "failed",
            {"buckets": [x.get("name") for x in no_enc[:35]]},
            remediation="Enable default bucket encryption (SSE-S3 or SSE-KMS) on all data buckets.",
        )
    else:
        signals["S3_DEFAULT_ENCRYPTION_DISABLED_ANY_BUCKET"] = _sig("passed", {"buckets_checked": len(buckets)})

    no_ver = [x for x in buckets if (x.get("versioning_status") or "").lower() != "enabled"] if buckets else []
    if not buckets and b.get("s3_buckets") is not None:
        signals["S3_VERSIONING_NOT_ENABLED_ALL_BUCKETS"] = _sig("passed", {"buckets": 0})
    elif not buckets:
        signals["S3_VERSIONING_NOT_ENABLED_ALL_BUCKETS"] = _sig("unknown", {}, remediation="No S3 bucket inventory.")
    elif no_ver:
        signals["S3_VERSIONING_NOT_ENABLED_ALL_BUCKETS"] = _sig(
            "failed",
            {"buckets": [x.get("name") for x in no_ver[:35]]},
            remediation="Enable versioning for buckets storing critical or compliance data; pair with lifecycle rules.",
        )
    else:
        signals["S3_VERSIONING_NOT_ENABLED_ALL_BUCKETS"] = _sig("passed", {"buckets_checked": len(buckets)})

    no_tls = [x for x in buckets if x.get("bucket_policy_denies_insecure_transport") is not True] if buckets else []
    if not buckets:
        signals["S3_DENY_INSECURE_TRANSPORT_NOT_ENFORCED"] = _sig("unknown", {}, remediation="No S3 bucket inventory.")
    elif no_tls:
        signals["S3_DENY_INSECURE_TRANSPORT_NOT_ENFORCED"] = _sig(
            "failed",
            {"buckets": [x.get("name") for x in no_tls[:35]]},
            remediation="Add bucket policies that deny aws:SecureTransport=false (or equivalent) for sensitive buckets.",
        )
    else:
        signals["S3_DENY_INSECURE_TRANSPORT_NOT_ENFORCED"] = _sig("passed", {"buckets_checked": len(buckets)})

    # --- CloudTrail ---
    trails = b.get("cloudtrail_trails") or []
    if not trails:
        signals["CLOUDTRAIL_CLOUDWATCH_LOGS_NOT_CONFIGURED"] = _sig("unknown", {}, remediation="CloudTrail trail metadata unavailable.")
    else:
        logging_trails = [t for t in trails if t.get("is_logging") is True]
        if not logging_trails:
            signals["CLOUDTRAIL_CLOUDWATCH_LOGS_NOT_CONFIGURED"] = _sig(
                "unknown",
                {"note": "no_active_logging_trail"},
                remediation="Enable a logging trail before integrating CloudWatch Logs.",
            )
        else:
            missing_cwl = [t for t in logging_trails if not (t.get("cloud_watch_logs_log_group_arn") or "").strip()]
            if missing_cwl:
                signals["CLOUDTRAIL_CLOUDWATCH_LOGS_NOT_CONFIGURED"] = _sig(
                    "failed",
                    {"trails": [t.get("name") for t in missing_cwl[:15]]},
                    remediation="Deliver CloudTrail logs to a CloudWatch Logs log group for search, metric filters, and alarms.",
                )
            else:
                signals["CLOUDTRAIL_CLOUDWATCH_LOGS_NOT_CONFIGURED"] = _sig(
                    "passed", {"logging_trails_with_cwl": len(logging_trails)}
                )

    if not trails:
        signals["CLOUDTRAIL_NOT_MULTI_REGION"] = _sig("unknown", {}, remediation="CloudTrail trail metadata unavailable.")
    else:
        ok = [t for t in trails if t.get("is_multi_region") is True and t.get("is_logging") is True]
        if ok:
            signals["CLOUDTRAIL_NOT_MULTI_REGION"] = _sig("passed", {"multiregion_logging_trails": len(ok)})
        else:
            signals["CLOUDTRAIL_NOT_MULTI_REGION"] = _sig(
                "failed",
                {"trails_sample": trails[:12]},
                remediation="Use a multi-Region organizational trail for management events across all Regions.",
            )

    # --- RDS ---
    rds = b.get("rds_instances_posture") or []
    if rds is None:
        for key in (
            "RDS_BACKUP_RETENTION_LT_7",
            "RDS_AUTO_MINOR_VERSION_UPGRADE_DISABLED",
            "RDS_MULTI_AZ_DISABLED",
            "RDS_DELETION_PROTECTION_DISABLED",
        ):
            signals[key] = _sig("unknown", {}, remediation="RDS inventory not collected.")
    elif not rds:
        for key in (
            "RDS_BACKUP_RETENTION_LT_7",
            "RDS_AUTO_MINOR_VERSION_UPGRADE_DISABLED",
            "RDS_MULTI_AZ_DISABLED",
            "RDS_DELETION_PROTECTION_DISABLED",
        ):
            signals[key] = _sig("passed", {"db_instances": 0})
    else:
        low_bak = [r for r in rds if int(r.get("backup_retention_period") or 0) < 7]
        signals["RDS_BACKUP_RETENTION_LT_7"] = (
            _sig(
                "failed",
                {"instances": low_bak[:30]},
                remediation="Increase automated backup retention to at least 7 days for production databases.",
            )
            if low_bak
            else _sig("passed", {"instances_checked": len(rds)})
        )
        no_auto = [r for r in rds if r.get("auto_minor_version_upgrade") is False]
        signals["RDS_AUTO_MINOR_VERSION_UPGRADE_DISABLED"] = (
            _sig(
                "failed",
                {"instances": no_auto[:30]},
                remediation="Enable auto minor version upgrade to receive security patches during maintenance windows.",
            )
            if no_auto
            else _sig("passed", {"instances_checked": len(rds)})
        )
        no_maz = [r for r in rds if r.get("multi_az") is False]
        signals["RDS_MULTI_AZ_DISABLED"] = (
            _sig(
                "failed",
                {"instances": no_maz[:30]},
                remediation="Enable Multi-AZ for production RDS instances that require high availability.",
            )
            if no_maz
            else _sig("passed", {"instances_checked": len(rds)})
        )
        no_del = [r for r in rds if r.get("deletion_protection") is False]
        signals["RDS_DELETION_PROTECTION_DISABLED"] = (
            _sig(
                "failed",
                {"instances": no_del[:30]},
                remediation="Enable deletion protection on production databases to prevent accidental drops.",
            )
            if no_del
            else _sig("passed", {"instances_checked": len(rds)})
        )

    # --- EBS / EC2 AMI ---
    ebs_bad = b.get("ebs_unencrypted_in_use_volumes") or []
    if ebs_bad is None:
        signals["EBS_IN_USE_VOLUME_UNENCRYPTED"] = _sig("unknown", {}, remediation="EBS volume encryption inventory not collected.")
    elif ebs_bad:
        signals["EBS_IN_USE_VOLUME_UNENCRYPTED"] = _sig(
            "failed",
            {"volumes": ebs_bad[:35]},
            remediation="Encrypt in-use EBS volumes (snapshot-copy with encryption or replace volumes) and enforce defaults.",
        )
    else:
        signals["EBS_IN_USE_VOLUME_UNENCRYPTED"] = _sig("passed", {"unencrypted_in_use": 0})

    ami_old = b.get("ec2_owned_ami_age_days_over_180") or []
    if ami_old is None:
        signals["EC2_OWNED_AMI_AGE_OVER_180_DAYS"] = _sig("unknown", {}, remediation="AMI age metadata not collected.")
    elif ami_old:
        signals["EC2_OWNED_AMI_AGE_OVER_180_DAYS"] = _sig(
            "failed",
            {"amis": ami_old[:30]},
            remediation="Refresh or deprecate AMIs older than 180 days; rebuild golden images with current patches.",
        )
    else:
        signals["EC2_OWNED_AMI_AGE_OVER_180_DAYS"] = _sig("passed", {"stale_owned_amis": 0})

    fl = b.get("vpc_flow_logs_account_summary")
    if fl is None:
        signals["VPC_FLOW_LOGS_DISABLED"] = _sig("unknown", {}, remediation="VPC Flow Logs inventory not collected.")
    elif int(fl.get("total_flow_logs") or 0) == 0:
        signals["VPC_FLOW_LOGS_DISABLED"] = _sig(
            "failed",
            {"regions_sampled": fl.get("regions_sampled")},
            remediation="Create VPC Flow Logs for production VPCs and ship to CloudWatch Logs or S3 for forensics.",
        )
    else:
        signals["VPC_FLOW_LOGS_DISABLED"] = _sig("passed", fl)

    dv = b.get("ec2_default_vpc_count")
    if dv is None:
        signals["EC2_DEFAULT_VPC_PRESENT"] = _sig("unknown", {}, remediation="Default VPC inventory not collected.")
    elif int(dv) > 0:
        signals["EC2_DEFAULT_VPC_PRESENT"] = _sig(
            "failed",
            {"default_vpc_count": dv},
            remediation="Remove or isolate default VPCs; use purpose-built VPCs with controlled routing and subnets.",
        )
    else:
        signals["EC2_DEFAULT_VPC_PRESENT"] = _sig("passed", {"default_vpc_count": 0})

    nat = b.get("ec2_nat_gateway_total_count")
    if nat is None:
        signals["NAT_GATEWAY_COUNT_COST_REVIEW"] = _sig("unknown", {}, remediation="NAT gateway inventory not collected.")
    elif int(nat) >= 3:
        signals["NAT_GATEWAY_COUNT_COST_REVIEW"] = _sig(
            "failed",
            {"nat_gateway_count": nat},
            remediation="NAT gateways incur hourly and data processing charges — consolidate egress paths where possible.",
        )
    else:
        signals["NAT_GATEWAY_COUNT_COST_REVIEW"] = _sig("passed", {"nat_gateway_count": nat})

    alb = b.get("ec2_alb_total_count")
    if alb is None:
        signals["ALB_COUNT_COST_REVIEW"] = _sig("unknown", {}, remediation="ELB inventory not collected.")
    elif int(alb) >= 8:
        signals["ALB_COUNT_COST_REVIEW"] = _sig(
            "failed",
            {"application_load_balancers": alb},
            remediation="Review idle or duplicate load balancers; remove unused ALBs to reduce fixed monthly cost.",
        )
    else:
        signals["ALB_COUNT_COST_REVIEW"] = _sig("passed", {"application_load_balancers": alb})

    ca = b.get("cloudwatch_metric_alarm_count")
    if ca is None:
        signals["CLOUDWATCH_METRIC_ALARMS_ABSENT"] = _sig("unknown", {}, remediation="CloudWatch alarms not enumerated.")
    elif int(ca) == 0:
        signals["CLOUDWATCH_METRIC_ALARMS_ABSENT"] = _sig(
            "failed",
            {"metric_alarms": 0},
            remediation="Create CloudWatch metric alarms for critical application, database, and cost anomalies.",
        )
    else:
        signals["CLOUDWATCH_METRIC_ALARMS_ABSENT"] = _sig("passed", {"metric_alarms": ca})

    gp2 = b.get("ebs_gp2_in_use_volume_count")
    if gp2 is None:
        signals["EBS_GP2_IN_USE_COST_REVIEW"] = _sig("unknown", {}, remediation="GP2 volume inventory not collected.")
    elif int(gp2) >= 5:
        signals["EBS_GP2_IN_USE_COST_REVIEW"] = _sig(
            "failed",
            {"gp2_in_use_volumes": gp2},
            remediation="Migrate gp2 volumes to gp3 where compatible for lower cost per GB with configurable IOPS/throughput.",
        )
    else:
        signals["EBS_GP2_IN_USE_COST_REVIEW"] = _sig("passed", {"gp2_in_use_volumes": gp2})

    ddb = b.get("dynamodb_pitr_disabled_tables") or []
    if ddb is None:
        signals["DYNAMODB_POINT_IN_TIME_RECOVERY_DISABLED"] = _sig("unknown", {}, remediation="DynamoDB PITR status not collected.")
    elif ddb:
        signals["DYNAMODB_POINT_IN_TIME_RECOVERY_DISABLED"] = _sig(
            "failed",
            {"tables": ddb[:35]},
            remediation="Enable point-in-time recovery on DynamoDB tables that store business-critical data.",
        )
    else:
        signals["DYNAMODB_POINT_IN_TIME_RECOVERY_DISABLED"] = _sig("passed", {"tables_checked": "sample"})

    ec_unenc = b.get("elasticache_unencrypted_clusters") or []
    if ec_unenc is None:
        signals["ELASTICACHE_ENCRYPTION_AT_REST_DISABLED"] = _sig("unknown", {}, remediation="ElastiCache inventory not collected.")
    elif ec_unenc:
        signals["ELASTICACHE_ENCRYPTION_AT_REST_DISABLED"] = _sig(
            "failed",
            {"clusters": ec_unenc[:25]},
            remediation="Create new encrypted replication groups and migrate; enable encryption at rest for sensitive caches.",
        )
    else:
        signals["ELASTICACHE_ENCRYPTION_AT_REST_DISABLED"] = _sig("passed", {"unencrypted_sample": 0})

    efs_bad = b.get("efs_unencrypted_file_systems") or []
    if efs_bad is None:
        signals["EFS_ENCRYPTION_AT_REST_DISABLED"] = _sig("unknown", {}, remediation="EFS inventory not collected.")
    elif efs_bad:
        signals["EFS_ENCRYPTION_AT_REST_DISABLED"] = _sig(
            "failed",
            {"file_systems": efs_bad[:25]},
            remediation="Use encrypted EFS file systems (KMS) for sensitive shared storage.",
        )
    else:
        signals["EFS_ENCRYPTION_AT_REST_DISABLED"] = _sig("passed", {"unencrypted": 0})

    sec_rows = b.get("secrets_manager_posture") or []
    if sec_rows is None:
        signals["SECRETS_MANAGER_ROTATION_DISABLED_COUNT"] = _sig("unknown", {}, remediation="Secrets Manager inventory not collected.")
    else:
        no_rot = [s for s in sec_rows if not s.get("rotation_enabled")]
        if len(no_rot) >= 6:
            signals["SECRETS_MANAGER_ROTATION_DISABLED_COUNT"] = _sig(
                "failed",
                {"secrets_without_rotation": len(no_rot), "sample": no_rot[:20]},
                remediation="Enable automatic rotation or document exceptions for secrets that support it.",
            )
        else:
            signals["SECRETS_MANAGER_ROTATION_DISABLED_COUNT"] = _sig("passed", {"secrets_without_rotation": len(no_rot)})

    lam = b.get("lambda_functions_posture") or []
    if lam is None:
        signals["LAMBDA_HIGH_ENV_VARS_WITHOUT_CMEK"] = _sig("unknown", {}, remediation="Lambda inventory not collected.")
    else:
        flagged = [f for f in lam if int(f.get("environment_variable_count") or 0) >= 8 and not (f.get("kms_key_arn") or "").strip()]
        if flagged:
            signals["LAMBDA_HIGH_ENV_VARS_WITHOUT_CMEK"] = _sig(
                "failed",
                {"functions": [x.get("function_name") for x in flagged[:25]]},
                remediation="Use environment variable encryption with a customer-managed KMS key for sensitive configuration.",
            )
        else:
            signals["LAMBDA_HIGH_ENV_VARS_WITHOUT_CMEK"] = _sig("passed", {"functions_checked": len(lam)})

    ecs = b.get("ecs_clusters_posture") or []
    if ecs is None:
        signals["ECS_CONTAINER_INSIGHTS_DISABLED_ANY"] = _sig("unknown", {}, remediation="ECS cluster inventory not collected.")
    elif not ecs:
        signals["ECS_CONTAINER_INSIGHTS_DISABLED_ANY"] = _sig("passed", {"clusters": 0})
    else:
        bad = [c for c in ecs if str(c.get("container_insights") or "").lower() in ("disabled", "")]
        if bad:
            signals["ECS_CONTAINER_INSIGHTS_DISABLED_ANY"] = _sig(
                "failed",
                {"clusters": bad[:25]},
                remediation="Enable Container Insights on ECS clusters for metrics, logs, and anomaly detection.",
            )
        else:
            signals["ECS_CONTAINER_INSIGHTS_DISABLED_ANY"] = _sig("passed", {"clusters_checked": len(ecs)})

    ec2_cnt = int(b.get("ec2_instance_inventory_count") or 0)
    ssm_cnt = b.get("ssm_managed_instance_count")
    if ssm_cnt is None:
        signals["SSM_COVERAGE_LOW_WHEN_EC2_PRESENT"] = _sig("unknown", {}, remediation="SSM managed instance count unavailable.")
    elif ec2_cnt >= 3 and int(ssm_cnt) == 0:
        signals["SSM_COVERAGE_LOW_WHEN_EC2_PRESENT"] = _sig(
            "failed",
            {"ec2_inventory_sample": ec2_cnt, "ssm_managed_instances": ssm_cnt},
            remediation="Use AWS Systems Manager to manage EC2 instances (patching, Session Manager, inventory).",
        )
    else:
        signals["SSM_COVERAGE_LOW_WHEN_EC2_PRESENT"] = _sig("passed", {"ec2_like": ec2_cnt, "ssm": ssm_cnt})

    wo = b.get("ec2_world_open_ingress") or []
    if wo is None:
        signals["EC2_SENSITIVE_INGRESS_WORLD_WIDE_COUNT_HIGH"] = _sig("unknown", {}, remediation="Security group scan unavailable.")
    elif len(wo) >= 25:
        signals["EC2_SENSITIVE_INGRESS_WORLD_WIDE_COUNT_HIGH"] = _sig(
            "failed",
            {"world_open_rules": len(wo)},
            remediation="Reduce broad Internet ingress across many security groups; prefer private connectivity and prefix lists.",
        )
    else:
        signals["EC2_SENSITIVE_INGRESS_WORLD_WIDE_COUNT_HIGH"] = _sig("passed", {"world_open_rules": len(wo)})

    posture = b.get("ec2_instance_posture") or []
    if posture is None:
        signals["EC2_MISSING_INSTANCE_PROFILE_WHEN_RUNNING"] = _sig("unknown", {}, remediation="EC2 instance posture not collected.")
    else:
        bad = [p for p in posture if (p.get("state") == "running") and p.get("missing_iam_instance_profile")]
        if bad:
            signals["EC2_MISSING_INSTANCE_PROFILE_WHEN_RUNNING"] = _sig(
                "failed",
                {"instances": [{"instance_id": x.get("instance_id"), "region": x.get("region")} for x in bad[:30]]},
                remediation="Attach least-privilege IAM instance profiles to running instances for auditable credentials.",
            )
        else:
            signals["EC2_MISSING_INSTANCE_PROFILE_WHEN_RUNNING"] = _sig("passed", {"running_without_profile": 0})

    if posture is None:
        signals["EC2_IMDSV2_NOT_REQUIRED_INSTANCES"] = _sig("unknown", {}, remediation="EC2 IMDS posture not collected.")
    else:
        bad = [p for p in posture if (p.get("http_tokens") or "").lower() != "required"]
        if bad:
            signals["EC2_IMDSV2_NOT_REQUIRED_INSTANCES"] = _sig(
                "failed",
                {"instances": [{"instance_id": x.get("instance_id"), "region": x.get("region")} for x in bad[:35]]},
                remediation="Require IMDSv2 (HttpTokens=required) on instances to reduce SSRF/metadata theft risk.",
            )
        else:
            signals["EC2_IMDSV2_NOT_REQUIRED_INSTANCES"] = _sig("passed", {"imdsv2_required_all": True})

    if posture is None:
        signals["EC2_PUBLIC_IPV4_ON_INSTANCES"] = _sig("unknown", {}, remediation="EC2 posture not collected.")
    else:
        pub = [p for p in posture if p.get("has_public_ip")]
        if pub:
            signals["EC2_PUBLIC_IPV4_ON_INSTANCES"] = _sig(
                "failed",
                {"instances": [{"instance_id": x.get("instance_id"), "region": x.get("region")} for x in pub[:35]]},
                remediation="Remove public IPv4 where possible; front workloads with ALB/CloudFront and use private subnets.",
            )
        else:
            signals["EC2_PUBLIC_IPV4_ON_INSTANCES"] = _sig("passed", {"public_instances": 0})

    if posture is None:
        signals["EC2_DETAILED_MONITORING_DISABLED_RUNNING"] = _sig("unknown", {}, remediation="EC2 monitoring state not collected.")
    else:
        bad = [
            p
            for p in posture
            if p.get("state") == "running" and str(p.get("monitoring_state") or "").lower() != "enabled"
        ]
        if bad:
            signals["EC2_DETAILED_MONITORING_DISABLED_RUNNING"] = _sig(
                "failed",
                {"instances": [{"instance_id": x.get("instance_id"), "region": x.get("region")} for x in bad[:35]]},
                remediation="Enable detailed monitoring for production instances to improve CloudWatch metric granularity.",
            )
        else:
            signals["EC2_DETAILED_MONITORING_DISABLED_RUNNING"] = _sig("passed", {"running_without_detailed": 0})

    if posture is None:
        signals["EC2_TERMINATION_PROTECTION_DISABLED_RUNNING"] = _sig("unknown", {}, remediation="Termination protection not collected.")
    else:
        bad = [
            p
            for p in posture
            if p.get("state") == "running" and p.get("disable_api_termination") is False
        ]
        if bad:
            signals["EC2_TERMINATION_PROTECTION_DISABLED_RUNNING"] = _sig(
                "failed",
                {"instances": [{"instance_id": x.get("instance_id"), "region": x.get("region")} for x in bad[:35]]},
                remediation="Enable termination protection for stateful or hard-to-replace production instances.",
            )
        else:
            signals["EC2_TERMINATION_PROTECTION_DISABLED_RUNNING"] = _sig("passed", {"running_unprotected": 0})

    sched = b.get("ec2_scheduled_instance_events") or []
    if sched is None:
        signals["EC2_SCHEDULED_MAINTENANCE_EVENTS_PRESENT"] = _sig("unknown", {}, remediation="EC2 scheduled events not collected.")
    elif sched:
        signals["EC2_SCHEDULED_MAINTENANCE_EVENTS_PRESENT"] = _sig(
            "failed",
            {"events": sched[:25]},
            remediation="Plan maintenance for instances with scheduled events; migrate or stop/start per AWS guidance.",
        )
    else:
        signals["EC2_SCHEDULED_MAINTENANCE_EVENTS_PRESENT"] = _sig("passed", {"scheduled_events": 0})

    gd = b.get("guardduty_summary") or {}
    if not gd:
        signals["GUARDDUTY_COVERAGE_LT_HALF_SAMPLED_REGIONS"] = _sig("unknown", {}, remediation="GuardDuty summary unavailable.")
    else:
        reg_n = len(gd.get("regions_sampled") or [])
        en_n = int(gd.get("enabled_regions_count") or 0)
        if reg_n and en_n * 2 < reg_n:
            signals["GUARDDUTY_COVERAGE_LT_HALF_SAMPLED_REGIONS"] = _sig(
                "failed",
                gd,
                remediation="Enable GuardDuty in more Regions where you run workloads (Organizations delegated admin recommended).",
            )
        else:
            signals["GUARDDUTY_COVERAGE_LT_HALF_SAMPLED_REGIONS"] = _sig("passed", {"enabled_regions": en_n, "sampled": reg_n})

    cred = b.get("iam_credential_analysis") or {}
    if not isinstance(cred, dict):
        signals["IAM_MULTI_ACTIVE_ACCESS_KEYS_PRESENT"] = _sig("unknown", {}, remediation="Credential analysis unavailable.")
    else:
        multi = cred.get("users_with_multiple_active_keys") or []
        if multi:
            signals["IAM_MULTI_ACTIVE_ACCESS_KEYS_PRESENT"] = _sig(
                "failed",
                {"users": multi[:40]},
                remediation="Deactivate duplicate access keys; keep a single active key per IAM user.",
            )
        else:
            signals["IAM_MULTI_ACTIVE_ACCESS_KEYS_PRESENT"] = _sig("passed", {"users": 0})

    pwd_key = cred.get("users_with_password_and_active_key") or [] if isinstance(cred, dict) else []
    if not isinstance(cred, dict):
        signals["IAM_PASSWORD_AND_PROGRAMMATIC_BOTH_ENABLED"] = _sig("unknown", {}, remediation="Credential analysis unavailable.")
    elif pwd_key:
        signals["IAM_PASSWORD_AND_PROGRAMMATIC_BOTH_ENABLED"] = _sig(
            "failed",
            {"users": pwd_key[:40]},
            remediation="Split console users from programmatic users; remove long-term keys from interactive accounts.",
        )
    else:
        signals["IAM_PASSWORD_AND_PROGRAMMATIC_BOTH_ENABLED"] = _sig("passed", {"users": 0})

    stale_keys = cred.get("access_keys_older_than_days") or [] if isinstance(cred, dict) else []
    if not isinstance(cred, dict):
        signals["IAM_ACCESS_KEYS_BEYOND_90_DAYS_ROTATION"] = _sig("unknown", {}, remediation="Credential analysis unavailable.")
    elif stale_keys:
        signals["IAM_ACCESS_KEYS_BEYOND_90_DAYS_ROTATION"] = _sig(
            "failed",
            {"keys": stale_keys[:40]},
            remediation="Rotate or remove IAM access keys older than 90 days; prefer IAM Roles / SSO for humans.",
        )
    else:
        signals["IAM_ACCESS_KEYS_BEYOND_90_DAYS_ROTATION"] = _sig("passed", {"stale_keys": 0})

    # --- Cost bundle (merged keys may be cost.* or plain) ---
    ec_cost = b.get("ec2_cost_signals") or b.get("cost.ec2_cost_signals")
    if not ec_cost:
        for key in (
            "COST_STOPPED_EC2_COUNT_HIGH",
            "COST_UNATTACHED_EBS_GB_HIGH",
            "COST_UNASSOCIATED_EIP_PRESENT",
            "COST_UNUSED_KEYPAIR_REGION_PRESENT",
        ):
            signals[key] = _sig("unknown", {}, remediation="EC2 cost signals not collected.")
    else:
        summ = ec_cost.get("summary") or {}
        stopped = int(summ.get("stopped_instance_count") or 0)
        signals["COST_STOPPED_EC2_COUNT_HIGH"] = (
            _sig(
                "failed",
                {"stopped_instances": stopped},
                remediation="Review long-stopped EC2 instances; snapshot and terminate or automate hibernate/start schedules.",
            )
            if stopped >= 8
            else _sig("passed", {"stopped_instances": stopped})
        )
        vols = int(summ.get("unattached_volume_count") or 0)
        gb = int(summ.get("unattached_volume_size_gb") or 0)
        signals["COST_UNATTACHED_EBS_GB_HIGH"] = (
            _sig(
                "failed",
                {"unattached_volumes": vols, "size_gb": gb},
                remediation="Snapshot and delete unattached EBS volumes or attach them to workloads that need the data.",
            )
            if gb >= 200 or vols >= 10
            else _sig("passed", {"unattached_volumes": vols, "size_gb": gb})
        )
        eip_n = int(summ.get("unassociated_elastic_ip_count") or 0)
        signals["COST_UNASSOCIATED_EIP_PRESENT"] = (
            _sig(
                "failed",
                {"unassociated_elastic_ips": eip_n},
                remediation="Release unassociated Elastic IPs to avoid hourly charges.",
            )
            if eip_n >= 1
            else _sig("passed", {"unassociated_elastic_ips": 0})
        )
        kpr = ec_cost.get("unused_key_pairs_by_region") or []
        if kpr:
            signals["COST_UNUSED_KEYPAIR_REGION_PRESENT"] = _sig(
                "failed",
                {"regions_with_unused_keys": kpr[:15]},
                remediation="Delete unused EC2 key pairs per Region after confirming no launch templates require them.",
            )
        else:
            signals["COST_UNUSED_KEYPAIR_REGION_PRESENT"] = _sig("passed", {"unused_key_regions": 0})

    rows_ce = b.get("cost_by_service_30d") or b.get("cost.cost_by_service_30d") or []
    if rows_ce is None:
        signals["COST_TOP_TWO_SERVICES_DOMINATE_SPEND"] = _sig("unknown", {}, remediation="Cost Explorer data not available.")
    elif not rows_ce:
        signals["COST_TOP_TWO_SERVICES_DOMINATE_SPEND"] = _sig("unknown", {}, remediation="No CE rows returned.")
    else:
        total = sum(float(r.get("amount") or 0) for r in rows_ce)
        if total <= 0:
            signals["COST_TOP_TWO_SERVICES_DOMINATE_SPEND"] = _sig("passed", {"total": total})
        else:
            top2 = sorted(rows_ce, key=lambda r: float(r.get("amount") or 0), reverse=True)[:2]
            share = sum(float(r.get("amount") or 0) for r in top2) / total
            if share >= 0.92:
                signals["COST_TOP_TWO_SERVICES_DOMINATE_SPEND"] = _sig(
                    "failed",
                    {"top_services": [t.get("service") for t in top2], "share": round(share, 3)},
                    remediation="Investigate architecture lock-in on two dominant services; diversify or optimize those stacks.",
                )
            else:
                signals["COST_TOP_TWO_SERVICES_DOMINATE_SPEND"] = _sig("passed", {"top_two_share": round(share, 3)})

    ta = b.get("trusted_advisor_cost_check_ids") or b.get("cost.trusted_advisor_cost_check_ids") or []
    if ta is None:
        signals["COST_TRUSTED_ADVISOR_CHECKS_UNAVAILABLE"] = _sig("unknown", {}, remediation="Trusted Advisor enumeration failed.")
    elif len(ta) == 0:
        signals["COST_TRUSTED_ADVISOR_CHECKS_UNAVAILABLE"] = _sig(
            "failed",
            {},
            remediation="Trusted Advisor cost checks require Business / Enterprise Support — consider upgrading for AWS cost guidance.",
        )
    else:
        signals["COST_TRUSTED_ADVISOR_CHECKS_UNAVAILABLE"] = _sig("passed", {"checks": len(ta)})

    budgets_ok = b.get("budgets_configured")
    if budgets_ok is None:
        signals["COST_BUDGETS_NOT_CONFIGURED"] = _sig("unknown", {}, remediation="Budget configuration unknown.")
    elif budgets_ok is False:
        signals["COST_BUDGETS_NOT_CONFIGURED"] = _sig(
            "failed",
            {},
            remediation="Create AWS Budgets with alerts for forecasted and actual spend.",
        )
    else:
        signals["COST_BUDGETS_NOT_CONFIGURED"] = _sig("passed", {"budgets": True})

    ri = b.get("ec2_reserved_instances_expiring") or []
    if ri is None:
        signals["COST_RESERVED_INSTANCES_EXPIRING_WINDOW"] = _sig("unknown", {}, remediation="Reserved Instance inventory unavailable.")
    elif len(ri) >= 3:
        signals["COST_RESERVED_INSTANCES_EXPIRING_WINDOW"] = _sig(
            "failed",
            {"expiring": ri[:20]},
            remediation="Plan renewals or Savings Plans before multiple RIs expire in the same window.",
        )
    else:
        signals["COST_RESERVED_INSTANCES_EXPIRING_WINDOW"] = _sig("passed", {"expiring_count": len(ri)})

    pc = [f for f in (lam or []) if int(f.get("provisioned_concurrency_units") or 0) > 0] if lam is not None else None
    if pc is None:
        signals["COST_LAMBDA_PROVISIONED_CONCURRENCY_UNITS_PRESENT"] = _sig("unknown", {}, remediation="Lambda inventory not collected.")
    elif pc:
        units = sum(int(f.get("provisioned_concurrency_units") or 0) for f in pc)
        signals["COST_LAMBDA_PROVISIONED_CONCURRENCY_UNITS_PRESENT"] = _sig(
            "failed",
            {"functions": [f.get("function_name") for f in pc[:20]], "total_units": units},
            remediation="Review provisioned concurrency cost; remove unused allocations or align with traffic patterns.",
        )
    else:
        signals["COST_LAMBDA_PROVISIONED_CONCURRENCY_UNITS_PRESENT"] = _sig("passed", {"provisioned_units": 0})

    # --- KMS supplemental ---
    kr = b.get("kms_customer_keys_rotation")
    if kr is None:
        signals["KMS_CUSTOMER_KEYS_CHECKED_LT_THREE"] = _sig("unknown", {}, remediation="KMS inventory incomplete.")
    else:
        checked = int(kr.get("customer_keys_checked") or 0)
        if checked > 0 and checked < 3:
            signals["KMS_CUSTOMER_KEYS_CHECKED_LT_THREE"] = _sig(
                "failed",
                kr,
                remediation="Sampled few customer KMS keys — verify broader key hygiene and rotation in all Regions.",
            )
        else:
            signals["KMS_CUSTOMER_KEYS_CHECKED_LT_THREE"] = _sig("passed", {"customer_keys_checked": checked})

    # --- S3 lifecycle missing (cost + hygiene) ---
    if not buckets:
        signals["S3_LIFECYCLE_NOT_CONFIGURED_ANY_BUCKET"] = _sig("unknown", {}, remediation="No S3 bucket inventory.")
    else:
        miss_lc = [x for x in buckets if x.get("lifecycle_configured") is False]
        if miss_lc:
            signals["S3_LIFECYCLE_NOT_CONFIGURED_ANY_BUCKET"] = _sig(
                "failed",
                {"buckets": [x.get("name") for x in miss_lc[:35]]},
                remediation="Add S3 lifecycle rules to transition or expire non-current versions and infrequent access objects.",
            )
        else:
            signals["S3_LIFECYCLE_NOT_CONFIGURED_ANY_BUCKET"] = _sig("passed", {"buckets_checked": len(buckets)})

    lw = b.get("ec2_launch_wizard_security_groups") or []
    if lw is None:
        signals["EC2_LAUNCH_WIZARD_SECURITY_GROUPS_PRESENT"] = _sig(
            "unknown", {}, remediation="Launch-wizard security group inventory unavailable."
        )
    elif len(lw) >= 4:
        signals["EC2_LAUNCH_WIZARD_SECURITY_GROUPS_PRESENT"] = _sig(
            "failed",
            {"groups": lw[:25], "count": len(lw)},
            remediation="Replace default launch-wizard-* groups with named security groups and least-privilege rules.",
        )
    else:
        signals["EC2_LAUNCH_WIZARD_SECURITY_GROUPS_PRESENT"] = _sig("passed", {"launch_wizard_groups": len(lw)})

    sg_hi = b.get("ec2_security_groups_high_rule_count") or []
    if sg_hi is None:
        signals["EC2_SECURITY_GROUP_RULE_BLOAT_PRESENT"] = _sig("unknown", {}, remediation="Security group rule bloat not sampled.")
    elif sg_hi:
        signals["EC2_SECURITY_GROUP_RULE_BLOAT_PRESENT"] = _sig(
            "failed",
            {"security_groups": sg_hi[:25]},
            remediation="Refactor high rule-count security groups to managed prefix lists and shared services to reduce misconfiguration risk.",
        )
    else:
        signals["EC2_SECURITY_GROUP_RULE_BLOAT_PRESENT"] = _sig("passed", {"bloated_groups": 0})

    sg_counts = b.get("ec2_security_group_counts_by_region") or []
    if not sg_counts:
        signals["EC2_SECURITY_GROUP_COUNT_PER_REGION_HIGH"] = _sig("unknown", {}, remediation="Regional SG counts unavailable.")
    else:
        hot = [r for r in sg_counts if int(r.get("security_group_count") or 0) >= 150]
        if hot:
            signals["EC2_SECURITY_GROUP_COUNT_PER_REGION_HIGH"] = _sig(
                "failed",
                {"regions": hot[:12]},
                remediation="High security group counts increase drift risk — archive unused VPCs and consolidate rules.",
            )
        else:
            signals["EC2_SECURITY_GROUP_COUNT_PER_REGION_HIGH"] = _sig("passed", {"regions_checked": len(sg_counts)})

    if lam is None:
        signals["LAMBDA_FUNCTION_URL_PUBLIC_AUTH_NONE"] = _sig("unknown", {}, remediation="Lambda inventory not collected.")
    else:
        bad = [f for f in lam if f.get("has_function_url") and str(f.get("function_url_auth_type") or "").upper() == "NONE"]
        if bad:
            signals["LAMBDA_FUNCTION_URL_PUBLIC_AUTH_NONE"] = _sig(
                "failed",
                {"functions": [x.get("function_name") for x in bad[:25]]},
                remediation="Require AWS_IAM auth on Lambda URLs or front them with API Gateway with authorizers.",
            )
        else:
            signals["LAMBDA_FUNCTION_URL_PUBLIC_AUTH_NONE"] = _sig("passed", {"public_urls": 0})

    certs = b.get("iam_server_certificates") or []
    if certs is None:
        signals["IAM_SERVER_CERTIFICATE_EXPIRES_30D"] = _sig("unknown", {}, remediation="Server certificate inventory unavailable.")
    else:
        soon = [c for c in certs if c.get("days_to_expiry") is not None and int(c["days_to_expiry"]) <= 30]
        if soon:
            signals["IAM_SERVER_CERTIFICATE_EXPIRES_30D"] = _sig(
                "failed",
                {"certificates": soon[:20]},
                remediation="Rotate or replace IAM server certificates before expiry to avoid TLS outages.",
            )
        else:
            signals["IAM_SERVER_CERTIFICATE_EXPIRES_30D"] = _sig("passed", {"expiring_within_30d": 0})

    if posture is None:
        signals["EC2_MULTI_ENI_INSTANCES_REVIEW"] = _sig("unknown", {}, remediation="EC2 posture not collected.")
    else:
        multi = [p for p in posture if int(p.get("network_interface_count") or 0) > 2]
        if multi:
            signals["EC2_MULTI_ENI_INSTANCES_REVIEW"] = _sig(
                "failed",
                {"instances": [{"instance_id": x.get("instance_id"), "region": x.get("region")} for x in multi[:25]]},
                remediation="Review multi-ENI instances for lateral movement and network complexity; document legitimate NIC layouts.",
            )
        else:
            signals["EC2_MULTI_ENI_INSTANCES_REVIEW"] = _sig("passed", {"multi_eni_instances": 0})

    ami_pub = b.get("ec2_owned_ami_posture") or []
    if ami_pub is None:
        signals["EC2_OWNED_AMI_PUBLIC_LAUNCH_PERMISSION"] = _sig("unknown", {}, remediation="Owned AMI posture unavailable.")
    else:
        pub = [a for a in ami_pub if a.get("public_launch_permission")]
        if pub:
            signals["EC2_OWNED_AMI_PUBLIC_LAUNCH_PERMISSION"] = _sig(
                "failed",
                {"images": pub[:20]},
                remediation="Remove public launch permissions from AMIs; share via private RAM or controlled accounts only.",
            )
        else:
            signals["EC2_OWNED_AMI_PUBLIC_LAUNCH_PERMISSION"] = _sig("passed", {"public_amis": 0})

    rds_rows = b.get("rds_instances_posture") or []
    if rds_rows is None:
        signals["RDS_PUBLIC_ACCESSIBILITY_ANY"] = _sig("unknown", {}, remediation="RDS inventory unavailable.")
    else:
        pub = [r for r in rds_rows if r.get("publicly_accessible")]
        if pub:
            signals["RDS_PUBLIC_ACCESSIBILITY_ANY"] = _sig(
                "failed",
                {"instances": pub[:25]},
                remediation="Disable public RDS endpoints; use private subnets and controlled security groups.",
            )
        else:
            signals["RDS_PUBLIC_ACCESSIBILITY_ANY"] = _sig("passed", {"public_instances": 0})

    if rds_rows is None:
        signals["RDS_STORAGE_UNENCRYPTED_ANY"] = _sig("unknown", {}, remediation="RDS inventory unavailable.")
    else:
        unenc = [r for r in rds_rows if r.get("storage_encrypted") is False]
        if unenc:
            signals["RDS_STORAGE_UNENCRYPTED_ANY"] = _sig(
                "failed",
                {"instances": unenc[:25]},
                remediation="Enable RDS storage encryption and plan migration for legacy instances.",
            )
        else:
            signals["RDS_STORAGE_UNENCRYPTED_ANY"] = _sig("passed", {"unencrypted_instances": 0})

    cfg_recs = b.get("config_recorders")
    if cfg_recs is None:
        signals["CONFIG_CONFIGURATION_RECORDER_NOT_RECORDING"] = _sig("unknown", {}, remediation="AWS Config status unavailable.")
    elif not cfg_recs:
        signals["CONFIG_CONFIGURATION_RECORDER_NOT_RECORDING"] = _sig(
            "failed",
            {},
            remediation="Enable AWS Config configuration recorder for resource change tracking.",
        )
    else:
        off = [r for r in cfg_recs if r.get("recording") is not True]
        if off:
            signals["CONFIG_CONFIGURATION_RECORDER_NOT_RECORDING"] = _sig(
                "failed",
                {"recorders": off[:12]},
                remediation="Start or fix AWS Config recorders so recording=true for all required scopes.",
            )
        else:
            signals["CONFIG_CONFIGURATION_RECORDER_NOT_RECORDING"] = _sig("passed", {"recorders": len(cfg_recs)})

    if b.get("security_hub_enabled") is True:
        signals["SECURITY_HUB_DISABLED"] = _sig("passed", {"enabled": True})
    elif b.get("security_hub_enabled") is False:
        signals["SECURITY_HUB_DISABLED"] = _sig(
            "failed",
            {"enabled": False},
            remediation="Enable AWS Security Hub to centralize findings from Config, GuardDuty, and partner integrations.",
        )
    else:
        signals["SECURITY_HUB_DISABLED"] = _sig("unknown", {}, remediation="Security Hub status unknown.")

    if not trails:
        signals["CLOUDTRAIL_NO_ACTIVE_LOGGING_TRAIL"] = _sig("unknown", {}, remediation="CloudTrail metadata unavailable.")
    elif not any(t.get("is_logging") is True for t in trails):
        signals["CLOUDTRAIL_NO_ACTIVE_LOGGING_TRAIL"] = _sig(
            "failed",
            {"trails": [t.get("name") for t in trails[:12]]},
            remediation="Start logging on at least one CloudTrail trail delivering management events.",
        )
    else:
        signals["CLOUDTRAIL_NO_ACTIVE_LOGGING_TRAIL"] = _sig(
            "passed", {"active_trails": sum(1 for t in trails if t.get("is_logging") is True)}
        )

    if posture is None:
        signals["EC2_RUNNING_INSTANCE_WITHOUT_KEY_NAME_REVIEW"] = _sig("unknown", {}, remediation="EC2 posture not collected.")
    else:
        no_key = [p for p in posture if p.get("state") == "running" and not (p.get("key_name") or "").strip()]
        if no_key:
            signals["EC2_RUNNING_INSTANCE_WITHOUT_KEY_NAME_REVIEW"] = _sig(
                "failed",
                {"instances": [{"instance_id": x.get("instance_id"), "region": x.get("region")} for x in no_key[:25]]},
                remediation="Prefer Session Manager over SSH keys; if SSH is required, attach an auditable key pair or use EC2 Instance Connect.",
            )
        else:
            signals["EC2_RUNNING_INSTANCE_WITHOUT_KEY_NAME_REVIEW"] = _sig("passed", {"running_without_key_name": 0})

    if lam is None:
        signals["LAMBDA_RESERVED_CONCURRENCY_SET_REVIEW"] = _sig("unknown", {}, remediation="Lambda inventory not collected.")
    else:
        resv = [
            f
            for f in lam
            if f.get("reserved_concurrent_executions") is not None
            and int(f["reserved_concurrent_executions"] or 0) > 0
        ]
        if resv:
            signals["LAMBDA_RESERVED_CONCURRENCY_SET_REVIEW"] = _sig(
                "failed",
                {"functions": [x.get("function_name") for x in resv[:25]]},
                remediation="Review reserved concurrency — it can throttle the rest of the account concurrency pool.",
            )
        else:
            signals["LAMBDA_RESERVED_CONCURRENCY_SET_REVIEW"] = _sig("passed", {"reserved_concurrency_functions": 0})

    # --- Lambda deprecated runtime count (subset) ---
    if lam is None:
        signals["LAMBDA_DEPRECATED_RUNTIME_INVENTORY"] = _sig("unknown", {}, remediation="Lambda inventory not collected.")
    else:
        legacy = {
            "nodejs4.3",
            "nodejs6.10",
            "nodejs8.10",
            "nodejs10.x",
            "nodejs12.x",
            "nodejs14.x",
            "python2.7",
            "python3.6",
            "python3.7",
            "dotnetcore2.1",
            "ruby2.5",
        }
        bad = [f for f in lam if (f.get("runtime") or "") in legacy]
        if bad:
            signals["LAMBDA_DEPRECATED_RUNTIME_INVENTORY"] = _sig(
                "failed",
                {"functions": [x.get("function_name") for x in bad[:25]]},
                remediation="Upgrade Lambda functions off deprecated runtimes before AWS blocks updates.",
            )
        else:
            signals["LAMBDA_DEPRECATED_RUNTIME_INVENTORY"] = _sig("passed", {"deprecated_functions": 0})

    sm = b.get("iam_summary") or {}
    if not isinstance(sm, dict):
        signals["IAM_ACCOUNT_USER_COUNT_HIGH"] = _sig("unknown", {}, remediation="IAM account summary unavailable.")
    else:
        users_n = int(sm.get("Users") or sm.get("User") or 0)
        if users_n >= 80:
            signals["IAM_ACCOUNT_USER_COUNT_HIGH"] = _sig(
                "failed",
                {"iam_users": users_n},
                remediation="Large IAM user counts increase audit burden — consolidate human access with IAM Identity Center (SSO).",
            )
        else:
            signals["IAM_ACCOUNT_USER_COUNT_HIGH"] = _sig("passed", {"iam_users": users_n})

    if not isinstance(sm, dict):
        signals["IAM_ACCOUNT_ROLE_COUNT_HIGH"] = _sig("unknown", {}, remediation="IAM account summary unavailable.")
    else:
        roles_n = int(sm.get("Roles") or 0)
        if roles_n >= 400:
            signals["IAM_ACCOUNT_ROLE_COUNT_HIGH"] = _sig(
                "failed",
                {"iam_roles": roles_n},
                remediation="High IAM role counts often indicate sprawl — inventory unused roles and enforce naming/ownership tags.",
            )
        else:
            signals["IAM_ACCOUNT_ROLE_COUNT_HIGH"] = _sig("passed", {"iam_roles": roles_n})

    if not buckets:
        signals["S3_BUCKET_COUNT_HIGH_COST_REVIEW"] = _sig("unknown", {}, remediation="No S3 bucket inventory.")
    elif len(buckets) >= 80:
        signals["S3_BUCKET_COUNT_HIGH_COST_REVIEW"] = _sig(
            "failed",
            {"bucket_count": len(buckets)},
            remediation="Very large bucket counts increase management cost — archive buckets, enforce naming standards, and centralize logging.",
        )
    else:
        signals["S3_BUCKET_COUNT_HIGH_COST_REVIEW"] = _sig("passed", {"bucket_count": len(buckets)})

    inv = int(b.get("ec2_instance_inventory_count") or 0)
    if inv >= 500:
        signals["EC2_INSTANCE_INVENTORY_COUNT_HIGH"] = _sig(
            "failed",
            {"instances_sampled_or_counted": inv},
            remediation="Large EC2 fleets benefit from Systems Manager, tagging automation, and delegated patch baselines.",
        )
    else:
        signals["EC2_INSTANCE_INVENTORY_COUNT_HIGH"] = _sig("passed", {"ec2_inventory": inv})

    dgs = b.get("ec2_default_security_groups") or []
    if dgs is None:
        signals["EC2_DEFAULT_SECURITY_GROUP_OPEN_INGRESS_REVIEW"] = _sig(
            "unknown", {}, remediation="Default security group inventory unavailable."
        )
    else:
        open_world = [g for g in dgs if g.get("open_to_world")]
        if open_world:
            signals["EC2_DEFAULT_SECURITY_GROUP_OPEN_INGRESS_REVIEW"] = _sig(
                "failed",
                {"default_security_groups": open_world[:20]},
                remediation="Default security groups should not permit Internet ingress; migrate rules to non-default groups.",
            )
        else:
            signals["EC2_DEFAULT_SECURITY_GROUP_OPEN_INGRESS_REVIEW"] = _sig("passed", {"open_default_groups": 0})

    # --- S3 public ACL / policy status (optional API) ---
    pub_acl = b.get("s3_bucket_public_acl_findings") or []
    if pub_acl is None:
        signals["S3_BUCKET_PUBLIC_ACL_OR_POLICY_ALLOWED"] = _sig("unknown", {}, remediation="S3 public access policy status not collected.")
    elif pub_acl:
        signals["S3_BUCKET_PUBLIC_ACL_OR_POLICY_ALLOWED"] = _sig(
            "failed",
            {"buckets": pub_acl[:30]},
            remediation="Block public ACLs/policies at account and bucket level; tighten bucket policies for sensitive data.",
        )
    else:
        signals["S3_BUCKET_PUBLIC_ACL_OR_POLICY_ALLOWED"] = _sig("passed", {"public_findings": 0})

    return signals
