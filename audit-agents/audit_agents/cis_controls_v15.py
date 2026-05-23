"""CIS Amazon Web Services Foundations Benchmark v1.5.0 — control ID hints.

Control numbers follow the CIS benchmark section numbering (e.g. 1.12, 2.1.1, 3.1).
Mappings are best-effort for custom rule packs; extend `CHECK_ID_TO_CIS` / `CSPM_SIGNAL_TO_CIS`.

References (maintenance):
- CIS Amazon Web Services Foundations Benchmark v1.5.0 (CIS WorkBench / PDF)
- AWS Security Hub CIS standard mapping tables
"""

from __future__ import annotations

from typing import Any

# check_id (rule `id` field) -> CIS v1.5 control identifier string
CHECK_ID_TO_CIS: dict[str, str] = {
    # Identity
    "SEC001_ROOT_ACCESS_KEYS": "1.12",
    "SEC002_ACCOUNT_PASSWORD_POLICY": "1.8",
    "SEC003_CONSOLE_USERS_MFA": "1.10",
    "SEC009_ACCESS_KEYS_ROTATION": "1.14",
    "SEC016_IAM_ADMINISTRATOR_ACCESS_USERS": "1.16",
    "SEC019_IAM_ACCESS_ANALYZER_ENABLED": "1.20",
    "SEC020_IAM_USERS_GROUP_MEMBERSHIP": "1.15",
    "SEC021_IAM_GROUPS_NO_INLINE_POLICIES": "1.17",
    "SEC022_IAM_COMPROMISED_KEY_QUARANTINE_ABSENT": "1.18",
    "SEC023_ROOT_ACCOUNT_MFA_ENABLED": "1.13",
    "SEC024_IAM_ACCESS_KEYS_MAX_AGE": "1.14",
    "SEC025_IAM_SINGLE_ACTIVE_ACCESS_KEY": "1.21",
    "SEC026_IAM_SPLIT_CONSOLE_AND_PROGRAMMATIC_ACCESS": "1.11",
    "SEC027_IAM_PASSWORD_POLICY_STRONG": "1.8",
    "SEC028_IAM_CROSS_ACCOUNT_TRUST_EXTERNAL_ID": "1.16",
    "SEC029_IAM_SERVER_CERTIFICATE_EXPIRY": "1.19",
    "SEC030_IAM_NO_EMPTY_GROUPS": "1.15",
    # Storage
    "SEC004_S3_ACCOUNT_PUBLIC_ACCESS_BLOCK": "2.1.1",
    "SEC010_S3_BUCKETS_PUBLIC_ACCESS_BLOCK": "2.1.1",
    "SEC040_S3_DEFAULT_ENCRYPTION": "2.1.1",
    "SEC041_S3_VERSIONING": "2.1.3",
    "SEC042_S3_SECURE_TRANSPORT_POLICY": "2.2.1",
    # Logging / monitoring
    "SEC006_CLOUDTRAIL_LOGGING": "3.1",
    "SEC017_CLOUDTRAIL_MULTIREGION_LOGGING": "3.1",
    "SEC018_CLOUDTRAIL_LOG_FILE_VALIDATION": "3.2",
    "SEC007_CONFIG_RECORDER": "3.5",
    "SEC008_SECURITY_HUB": "3.6",
    "SEC011_GUARDDUTY_ENABLED": "3.6",
    # Networking
    "SEC005_DEFAULT_SG_RESTRICTIVE": "5.2",
    "SEC014_SG_SSH_OPEN_INTERNET": "5.2",
    "SEC048_EC2_NON_SSH_SENSITIVE_PORTS_WORLD": "5.2",
    "SEC049_EC2_SG_WIDE_PORT_RANGE_WORLD": "5.2",
    "SEC050_EC2_LAUNCH_WIZARD_SECURITY_GROUPS": "5.2",
    "SEC051_EC2_SECURITY_GROUP_RULE_BLOAT": "5.2",
    "SEC052_EC2_SECURITY_GROUPS_REGION_COUNT": "5.2",
    "SEC054_EC2_MINIMIZE_PUBLIC_IPV4": "5.2",
    "SEC055_EC2_PUBLIC_SUBNET_AND_PUBLIC_IP": "5.2",
    "SEC056_EC2_INSTANCES_DEFAULT_SECURITY_GROUP": "5.2",
    # Data protection
    "SEC012_KMS_CMK_ROTATION": "3.6",
    "SEC013_EBS_DEFAULT_ENCRYPTION": "2.2.1",
    "SEC015_RDS_PUBLIC_OR_UNENCRYPTED": "2.3.1",
    # Compute
    "SEC043_EC2_IMDSV2_REQUIRED": "5.6",
    "SEC053_EC2_INSTANCE_PROFILE_ATTACHED": "5.3",
    "SEC057_EC2_TERMINATION_PROTECTION_RUNNING": "5.4",
    "SEC058_EC2_DETAILED_MONITORING": "5.3",
    "SEC059_EC2_SCHEDULED_EVENTS": "5.3",
    "SEC060_EC2_OWNED_AMI_ENCRYPTED": "2.2.1",
    "SEC061_EC2_OWNED_AMI_NOT_PUBLIC": "2.2.1",
    "SEC062_EC2_MULTIPLE_ENIS_REVIEW": "5.3",
    "SEC063_EC2_MODERN_INSTANCE_FAMILY": "5.3",
    "SEC064_EC2_INSTANCE_LAUNCH_AGE": "5.3",
    # Lambda / ECS / SSM / Secrets
    "SEC031_LAMBDA_FUNCTION_URL_IAM": "5.4",
    "SEC032_LAMBDA_EXECUTION_ROLE": "5.4",
    "SEC033_LAMBDA_DEAD_LETTER": "5.4",
    "SEC034_LAMBDA_ENV_CMEK": "3.6",
    "SEC035_LAMBDA_XRAY_TRACING": "5.4",
    "SEC036_LAMBDA_SUPPORTED_RUNTIME": "5.4",
    "SEC037_LAMBDA_ROLE_NO_INLINE": "1.16",
    "SEC038_LAMBDA_ROLE_NO_ADMIN_ACCESS": "1.16",
    "SEC039_LAMBDA_CODE_SIGNING_ZIP": "5.4",
    "SEC044_ECS_CONTAINER_INSIGHTS": "5.4",
    "SEC045_SSM_EC2_MANAGED_COVERAGE": "5.3",
    "SEC046_SECRETS_MANAGER_ROTATION": "3.6",
    "SEC047_SECRETS_MANAGER_CUSTOMER_KMS": "3.6",
    # Cost (CIS cost is limited; map to closest operational / logging themes)
    "COST001_AWS_BUDGETS": "1.22",
    "COST002_COST_EXPLORER_DATA": "1.22",
    "COST003_SERVICE_SPEND_CONCENTRATION": "1.22",
    "COST004_ZERO_OR_LOW_SPEND_SIGNAL": "1.22",
    "COST005_UNASSOCIATED_ELASTIC_IPS": "1.22",
    "COST006_UNATTACHED_EBS_VOLUMES": "1.22",
    "COST007_STOPPED_EC2_REVIEW": "1.22",
    "COST008_S3_LIFECYCLE": "2.1.3",
    "COST009_LAMBDA_PROVISIONED_CONCURRENCY": "1.22",
    "COST013_EC2_RESERVED_INSTANCES_EXPIRING": "1.22",
    "COST014_EC2_UNUSED_KEY_PAIRS": "1.14",
    "COST015_EC2_UNATTACHED_ENI": "1.22",
    "COST016_EC2_INSTANCE_LIMIT_HEADROOM": "1.22",
}

# CSPM signal keys (AUD-001 pack) -> CIS v1.5 control (approximate alignment)
CSPM_SIGNAL_TO_CIS: dict[str, str] = {
    "IAM_CREDENTIAL_REPORT_MISSING": "1.8",
    "IAM_STALE_CONSOLE_PASSWORD_90D": "1.10",
    "IAM_USER_INLINE_POLICIES_PRESENT": "1.16",
    "IAM_INLINE_POLICY_WILDCARD_ACTION": "1.16",
    "IAM_ATTACHED_CUSTOMER_POLICY_WILDCARD_ACTION": "1.16",
    "S3_BUCKET_SERVER_ACCESS_LOGGING_DISABLED": "3.1",
    "S3_DEFAULT_ENCRYPTION_DISABLED_ANY_BUCKET": "2.1.1",
    "S3_VERSIONING_NOT_ENABLED_ALL_BUCKETS": "2.1.3",
    "S3_DENY_INSECURE_TRANSPORT_NOT_ENFORCED": "2.2.1",
    "CLOUDTRAIL_CLOUDWATCH_LOGS_NOT_CONFIGURED": "3.4",
    "CLOUDTRAIL_NOT_MULTI_REGION": "3.1",
    "CLOUDTRAIL_NO_ACTIVE_LOGGING_TRAIL": "3.1",
    "RDS_BACKUP_RETENTION_LT_7": "2.3.1",
    "RDS_AUTO_MINOR_VERSION_UPGRADE_DISABLED": "2.3.1",
    "RDS_MULTI_AZ_DISABLED": "2.3.1",
    "RDS_DELETION_PROTECTION_DISABLED": "2.3.1",
    "RDS_PUBLIC_ACCESSIBILITY_ANY": "2.3.1",
    "RDS_STORAGE_UNENCRYPTED_ANY": "2.3.1",
    "EBS_IN_USE_VOLUME_UNENCRYPTED": "2.2.1",
    "EC2_OWNED_AMI_AGE_OVER_180_DAYS": "2.2.1",
    "EC2_OWNED_AMI_PUBLIC_LAUNCH_PERMISSION": "2.2.1",
    "VPC_FLOW_LOGS_DISABLED": "3.1",
    "EC2_DEFAULT_VPC_PRESENT": "5.1",
    "EC2_DEFAULT_SECURITY_GROUP_OPEN_INGRESS_REVIEW": "5.2",
    "EC2_LAUNCH_WIZARD_SECURITY_GROUPS_PRESENT": "5.2",
    "EC2_SECURITY_GROUP_RULE_BLOAT_PRESENT": "5.2",
    "EC2_SECURITY_GROUP_COUNT_PER_REGION_HIGH": "5.2",
    "EC2_SENSITIVE_INGRESS_WORLD_WIDE_COUNT_HIGH": "5.2",
    "EC2_MISSING_INSTANCE_PROFILE_WHEN_RUNNING": "5.3",
    "EC2_IMDSV2_NOT_REQUIRED_INSTANCES": "5.6",
    "EC2_PUBLIC_IPV4_ON_INSTANCES": "5.2",
    "EC2_DETAILED_MONITORING_DISABLED_RUNNING": "5.3",
    "EC2_TERMINATION_PROTECTION_DISABLED_RUNNING": "5.4",
    "EC2_SCHEDULED_MAINTENANCE_EVENTS_PRESENT": "5.3",
    "EC2_MULTI_ENI_INSTANCES_REVIEW": "5.3",
    "EC2_RUNNING_INSTANCE_WITHOUT_KEY_NAME_REVIEW": "5.3",
    "GUARDDUTY_COVERAGE_LT_HALF_SAMPLED_REGIONS": "3.6",
    "IAM_MULTI_ACTIVE_ACCESS_KEYS_PRESENT": "1.21",
    "IAM_PASSWORD_AND_PROGRAMMATIC_BOTH_ENABLED": "1.11",
    "IAM_ACCESS_KEYS_BEYOND_90_DAYS_ROTATION": "1.14",
    "IAM_ACCOUNT_USER_COUNT_HIGH": "1.15",
    "IAM_ACCOUNT_ROLE_COUNT_HIGH": "1.16",
    "IAM_SERVER_CERTIFICATE_EXPIRES_30D": "1.19",
    "S3_BUCKET_PUBLIC_ACL_OR_POLICY_ALLOWED": "2.1.1",
    "S3_LIFECYCLE_NOT_CONFIGURED_ANY_BUCKET": "2.1.3",
    "S3_BUCKET_COUNT_HIGH_COST_REVIEW": "2.1.1",
    "CONFIG_CONFIGURATION_RECORDER_NOT_RECORDING": "3.5",
    "SECURITY_HUB_DISABLED": "3.6",
    "DYNAMODB_POINT_IN_TIME_RECOVERY_DISABLED": "2.1.3",
    "ELASTICACHE_ENCRYPTION_AT_REST_DISABLED": "2.3.1",
    "EFS_ENCRYPTION_AT_REST_DISABLED": "2.1.1",
    "SECRETS_MANAGER_ROTATION_DISABLED_COUNT": "3.6",
    "LAMBDA_HIGH_ENV_VARS_WITHOUT_CMEK": "3.6",
    "LAMBDA_FUNCTION_URL_PUBLIC_AUTH_NONE": "5.4",
    "LAMBDA_DEPRECATED_RUNTIME_INVENTORY": "5.4",
    "LAMBDA_RESERVED_CONCURRENCY_SET_REVIEW": "5.4",
    "ECS_CONTAINER_INSIGHTS_DISABLED_ANY": "5.4",
    "SSM_COVERAGE_LOW_WHEN_EC2_PRESENT": "5.3",
    "KMS_CUSTOMER_KEYS_CHECKED_LT_THREE": "3.6",
    "CLOUDWATCH_METRIC_ALARMS_ABSENT": "3.3",
    "EBS_GP2_IN_USE_COST_REVIEW": "1.22",
    "NAT_GATEWAY_COUNT_COST_REVIEW": "1.22",
    "ALB_COUNT_COST_REVIEW": "1.22",
    "COST_STOPPED_EC2_COUNT_HIGH": "1.22",
    "COST_UNATTACHED_EBS_GB_HIGH": "1.22",
    "COST_UNASSOCIATED_EIP_PRESENT": "1.22",
    "COST_UNUSED_KEYPAIR_REGION_PRESENT": "1.14",
    "COST_TOP_TWO_SERVICES_DOMINATE_SPEND": "1.22",
    "COST_TRUSTED_ADVISOR_CHECKS_UNAVAILABLE": "1.22",
    "COST_BUDGETS_NOT_CONFIGURED": "1.22",
    "COST_RESERVED_INSTANCES_EXPIRING_WINDOW": "1.22",
    "COST_LAMBDA_PROVISIONED_CONCURRENCY_UNITS_PRESENT": "1.22",
    "EC2_INSTANCE_INVENTORY_COUNT_HIGH": "1.22",
}


def aggregate_cis_compliance(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """CIS AWS Foundations Benchmark v1.5 style score over CIS-mapped checks only."""
    mapped = [f for f in findings if f.get("cis_control")]
    n = len(mapped)
    empty = {
        "framework": "CIS AWS Foundations Benchmark",
        "version": "1.5.0",
        "score_percent": None,
        "mapped_checks_total": 0,
        "mapped_checks_passed": 0,
        "mapped_checks_failed": 0,
        "mapped_checks_unknown": 0,
        "failing_control_count": 0,
        "failing_control_ids": [],
        "band": None,
    }
    if n == 0:
        return empty
    passed = sum(1 for f in mapped if f.get("status") == "passed")
    failed = sum(1 for f in mapped if f.get("status") == "failed")
    unknown = sum(1 for f in mapped if f.get("status") == "unknown")
    score = round(100.0 * passed / n, 1)
    failed_cis: set[str] = set()
    for f in mapped:
        if f.get("status") == "failed":
            c = f.get("cis_control")
            if isinstance(c, str) and c.strip():
                failed_cis.add(c.strip())
    fc = sorted(failed_cis)
    # Red <50%, amber 50–80% inclusive, green >80% (CIS score card spec).
    if score < 50.0:
        band = "red"
    elif score <= 80.0:
        band = "amber"
    else:
        band = "green"
    return {
        "framework": "CIS AWS Foundations Benchmark",
        "version": "1.5.0",
        "score_percent": score,
        "mapped_checks_total": n,
        "mapped_checks_passed": passed,
        "mapped_checks_failed": failed,
        "mapped_checks_unknown": unknown,
        "failing_control_count": len(fc),
        "failing_control_ids": fc,
        "band": band,
    }


def resolve_cis_control(rule: dict[str, Any]) -> str | None:
    """Return CIS v1.5 control id for a rule definition, or None if unmapped."""
    raw = rule.get("cis_control")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    rid = rule.get("id")
    if isinstance(rid, str) and rid in CHECK_ID_TO_CIS:
        return CHECK_ID_TO_CIS[rid]
    sig = rule.get("cspm_signal")
    if isinstance(sig, str) and sig in CSPM_SIGNAL_TO_CIS:
        return CSPM_SIGNAL_TO_CIS[sig]
    return None
