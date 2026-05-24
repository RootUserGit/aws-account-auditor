from __future__ import annotations

import csv
import inspect
import io
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

import yaml

from audit_agents.cis_controls_v15 import resolve_cis_control

logger = logging.getLogger(__name__)

# End-of-life / deprecated Lambda runtimes (expand over time).
_LEGACY_EC2_INSTANCE_PREFIXES: tuple[str, ...] = (
    "t1.",
    "m1.",
    "m2.",
    "m3.",
    "c1.",
    "cc1.",
    "cc2.",
    "cg1.",
    "g2.",
    "cr1.",
    "hi1.",
    "hs1.",
    "i2.",
)


def _ec2_instance_type_legacy(instance_type: str) -> bool:
    x = (instance_type or "").strip().lower()
    return bool(x) and any(x.startswith(p) for p in _LEGACY_EC2_INSTANCE_PREFIXES)


_DEPRECATED_LAMBDA_RUNTIMES: frozenset[str] = frozenset(
    {
        "nodejs4.3",
        "nodejs4.3-edge",
        "nodejs6.10",
        "nodejs8.10",
        "nodejs10.x",
        "nodejs12.x",
        "nodejs14.x",
        "python2.7",
        "python3.6",
        "python3.7",
        "dotnetcore1.0",
        "dotnetcore2.0",
        "dotnetcore2.1",
        "dotnetcore3.1",
        "ruby2.5",
        "ruby2.7",
        "go1.x",
        "provided",
    }
)

RuleEvalResult = Tuple[str, Dict[str, Any], Optional[str], str]

EVALUATORS: Dict[str, Callable[[Dict[str, Any]], RuleEvalResult]] = {}


def _days_since(value: Any) -> int | None:
    """Days from a datetime or ISO string to now (UTC)."""
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
    now = datetime.now(timezone.utc)
    return max(0, (now - dt).days)


def _normalize_mfa_row(raw: Any) -> dict[str, Any]:
    if isinstance(raw, str):
        return {"user_name": raw}
    if isinstance(raw, dict):
        return dict(raw)
    return {"user_name": str(raw)}


def _playbook(*steps: str) -> dict[str, Any]:
    return {"remediation_playbook": list(steps)}


def register(name: str) -> Callable:
    def deco(fn: Callable[[dict[str, Any]], RuleEvalResult]) -> Any:
        EVALUATORS[name] = fn
        return fn

    return deco


@register("iam_root_no_access_keys")
def iam_root_no_access_keys(ev: dict[str, Any]) -> RuleEvalResult:
    sm = ev.get("iam_summary")
    if not sm:
        return ("unknown", {}, None, "IAM account summary not available.")
    keys = sm.get("AccountAccessKeysPresent")
    if keys is None:
        return ("unknown", {}, None, "Missing AccountAccessKeysPresent in summary.")
    n = int(keys)
    if n == 0:
        return ("passed", {"root_access_keys": n}, None, "")
    return (
        "failed",
        {"root_access_keys": n},
        None,
        "Remove root user access keys; use IAM users or federation with temporary credentials.",
    )


@register("iam_password_policy_configured")
def iam_password_policy_configured(ev: dict[str, Any]) -> RuleEvalResult:
    pol = ev.get("iam_password_policy")
    if pol is None:
        return ("failed", {}, None, "Create an IAM account password policy enforcing complexity and rotation.")
    return ("passed", {"policy_keys": list(pol.keys())}, None, "")


@register("iam_console_users_have_mfa")
def iam_console_users_have_mfa(ev: dict[str, Any]) -> RuleEvalResult:
    users = ev.get("iam_users_without_mfa")
    if users is None:
        return ("unknown", {}, None, "Could not evaluate MFA for users.")
    if len(users) == 0:
        return ("passed", {"users_without_mfa": 0}, None, "")
    details: list[dict[str, Any]] = []
    for raw in users[:50]:
        row = _normalize_mfa_row(raw)
        row["user_age_days"] = _days_since(row.get("create_date"))
        pwd = row.get("password_last_used")
        if pwd not in (None, "", "no_information"):
            row["days_since_password_use"] = _days_since(pwd)
        details.append(row)
    return (
        "failed",
        {"users_without_mfa": details, "total_without_mfa": len(users)},
        None,
        f"Enable MFA for {len(users)} IAM user(s) with console access.",
    )


@register("s3_account_public_access_block_enabled")
def s3_account_public_access_block_enabled(ev: dict[str, Any]) -> RuleEvalResult:
    pab = ev.get("s3_account_public_access_block")
    if pab is None:
        return (
            "unknown",
            {},
            None,
            "Account-level S3 public access block not available or not permitted.",
        )
    required = [
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    ]
    if all(pab.get(k) is True for k in required):
        return ("passed", pab, None, "")
    return (
        "failed",
        pab,
        None,
        "Enable all Block Public Access settings at the S3 account level.",
    )


@register("s3_buckets_have_public_access_block")
def s3_buckets_have_public_access_block(ev: dict[str, Any]) -> RuleEvalResult:
    if "s3_buckets" not in ev:
        return ("unknown", {}, None, "No bucket list collected.")
    buckets = ev.get("s3_buckets") or []
    missing = []
    for b in buckets:
        name = b.get("name")
        if b.get("public_access_block_error") == "NoSuchPublicAccessBlockConfiguration":
            missing.append(name)
        elif "public_access_block" not in b and b.get("public_access_block_error"):
            missing.append(name)
    if not missing:
        return ("passed", {"buckets_checked": len(buckets)}, None, "")
    missing_set = {m for m in missing if m}
    detail_rows = [b for b in buckets if b.get("name") in missing_set][:30]
    return (
        "failed",
        {
            "buckets_missing_pab": [m for m in missing if m][:30],
            "buckets_detail": detail_rows,
            "total_non_compliant": len(missing_set),
        },
        None,
        "Configure S3 Block Public Access on buckets missing settings.",
    )


@register("ec2_default_sg_no_open_ingress")
def ec2_default_sg_no_open_ingress(ev: dict[str, Any]) -> RuleEvalResult:
    sgs = ev.get("ec2_default_security_groups") or []
    if not sgs:
        return ("unknown", {}, None, "No default security group data in sampled regions.")
    bad = [g for g in sgs if g.get("open_to_world")]
    if not bad:
        return ("passed", {"default_sgs_checked": len(sgs)}, None, "")
    return (
        "failed",
        {"open_default_sgs": bad[:20]},
        None,
        "Default security groups should not allow ingress from 0.0.0.0/0; use dedicated groups.",
    )


@register("cloudtrail_logging_enabled")
def cloudtrail_logging_enabled(ev: dict[str, Any]) -> RuleEvalResult:
    trails = ev.get("cloudtrail_trails") or []
    if not trails:
        return ("unknown", {}, None, "CloudTrail metadata unavailable.")
    logging = [t for t in trails if t.get("is_logging") is True]
    if logging:
        return ("passed", {"logging_trails": len(logging)}, None, "")
    if all(t.get("is_logging") is None for t in trails):
        return ("unknown", {"cloudtrail_trails": trails}, None, "Could not read trail logging status.")
    return ("failed", {"trails": len(trails)}, None, "Enable management event logging on at least one multi-Region trail.")


@register("config_recorder_on")
def config_recorder_on(ev: dict[str, Any]) -> RuleEvalResult:
    recs = ev.get("config_recorders")
    if recs is None:
        return ("unknown", {}, None, "AWS Config not available or not authorized.")
    on = [r for r in recs if r.get("recording") is True]
    if on:
        return ("passed", {"recorders": len(on)}, None, "")
    return (
        "failed",
        {"config_recorders": recs},
        None,
        "Turn on AWS Config recorders for resource inventory and compliance.",
    )


@register("security_hub_enabled_check")
def security_hub_enabled_check(ev: dict[str, Any]) -> RuleEvalResult:
    if ev.get("security_hub_enabled") is True:
        return ("passed", {"enabled": True}, None, "")
    if ev.get("security_hub_enabled") is False:
        return ("failed", {"enabled": False}, None, "Enable AWS Security Hub in this Region/account.")
    return ("unknown", {}, None, "Security Hub status unknown.")


@register("iam_access_keys_rotation_heuristic")
def iam_access_keys_rotation_heuristic(ev: dict[str, Any]) -> RuleEvalResult:
    raw = ev.get("iam_credential_report_csv")
    if not raw:
        return ("unknown", {}, None, "Credential report not available.")
    reader = csv.DictReader(io.StringIO(raw))
    stale_detail: list[dict[str, Any]] = []
    for row in reader:
        if row.get("user") == "<root_account>":
            continue
        if row.get("access_key_1_active") == "true":
            last_used = row.get("access_key_1_last_used", "") or ""
            if last_used in ("N/A", "", "no_information"):
                rot = row.get("access_key_1_last_rotated") or ""
                created = row.get("user_creation_time") or ""
                stale_detail.append(
                    {
                        "user_name": row.get("user", ""),
                        "access_key_1_last_rotated": rot,
                        "access_key_1_last_used": last_used,
                        "user_creation_time": created,
                        "key_age_days": _days_since(rot) if rot not in ("N/A", "", "not_supported") else None,
                    }
                )
    if not stale_detail:
        return ("passed", {"suspect_users": 0}, None, "")
    return (
        "failed",
        {
            "access_key_concerns": stale_detail[:30],
            "total_flagged": len(stale_detail),
        },
        None,
        "Review IAM user access keys; rotate or remove unused keys.",
    )


@register("budgets_present")
def budgets_present(ev: dict[str, Any]) -> RuleEvalResult:
    if ev.get("budgets_configured") is True:
        return ("passed", {"budgets": ev.get("budgets", [])}, None, "")
    if ev.get("budgets_configured") is False and ev.get("budgets") == []:
        return ("failed", {}, None, "Create AWS Budgets for key services or accounts.")
    return ("unknown", {}, None, "Could not determine budget configuration.")


@register("cost_explorer_has_data")
def cost_explorer_has_data(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("cost_by_service_30d") or []
    if rows:
        return ("passed", {"rows": len(rows)}, None, "")
    errs = ev.get("_errors") or ev.get("_collector_errors") or []
    if any("ce." in str(e) for e in errs):
        return ("unknown", {}, None, "Cost Explorer permission or data not available.")
    return ("failed", {}, None, "No Cost Explorer usage returned for the window — verify billing/cost categories.")


@register("cost_top_service_share_high")
def cost_top_service_share_high(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("cost_by_service_30d") or []
    if not rows:
        return ("unknown", {}, None, "No cost breakdown.")
    total = sum(r.get("amount", 0) for r in rows)
    if total <= 0:
        return ("passed", {"total": total}, None, "")
    top = max(rows, key=lambda r: r.get("amount", 0))
    share = top.get("amount", 0) / total
    if share > 0.85:
        return (
            "failed",
            {"top_service": top.get("service"), "share": round(share, 3)},
            None,
            "Review dominant service spend for rightsizing, reservations, or architecture efficiency.",
        )
    return ("passed", {"top_share": round(share, 3)}, None, "")


@register("guardduty_enabled")
def guardduty_enabled(ev: dict[str, Any]) -> RuleEvalResult:
    gs = ev.get("guardduty_summary")
    if gs is None:
        return ("unknown", {}, None, "GuardDuty inventory was not collected or permission was denied.")
    if int(gs.get("enabled_regions_count") or 0) >= 1:
        ev_out = {"enabled_regions": gs.get("enabled_regions", [])}
        return ("passed", ev_out, None, "")
    pb = _playbook(
        "Enable Amazon GuardDuty in each active Region from the GuardDuty console or IaC (AWS Organizations delegated admin recommended for multi-account).",
        "Use S3 export + KMS CMK and optionally publish findings to Security Hub for centralized workflows.",
        "Tune suppression rules only after triage so real threats are not hidden; integrate findings with your SOC ticketing pipeline.",
    )
    return (
        "failed",
        {**gs, **pb},
        None,
        "No enabled GuardDuty detector was found in sampled Regions — enable threat detection across your footprint.",
    )


@register("kms_customer_managed_rotation")
def kms_customer_managed_rotation(ev: dict[str, Any]) -> RuleEvalResult:
    kr = ev.get("kms_customer_keys_rotation")
    if kr is None:
        return ("unknown", {}, None, "KMS key rotation status could not be read.")
    bad = kr.get("keys_without_rotation") or []
    if not bad:
        return ("passed", {"customer_keys_checked": kr.get("customer_keys_checked", 0)}, None, "")
    pb = _playbook(
        "For symmetric CMKs, enable automatic key rotation (annual material rotation) unless you have a documented exception.",
        "Prefer envelope encryption with AWS-managed keys where CMK control adds no value; reserve CMKs for regulated data.",
        "Use IAM and KMS key policies that deny wildcard principals; enable CloudTrail data events on KMS where required for audits.",
    )
    return (
        "failed",
        {"keys_without_rotation": bad, **pb},
        None,
        "One or more customer-managed KMS keys have rotation disabled.",
    )


@register("ebs_default_encryption_all_sampled_regions")
def ebs_default_encryption_all_sampled_regions(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("ebs_default_encryption_by_region")
    if not rows:
        return ("unknown", {}, None, "EBS default encryption could not be evaluated.")
    explicit_false = [r for r in rows if r.get("ebs_encryption_by_default") is False]
    if explicit_false:
        pb = _playbook(
            "Turn on EBS encryption by default per Region (EC2 console → Account attributes → EBS encryption) and enforce via SCP where appropriate.",
            "Ensure CMKs used for default encryption have rotation and least-privilege key policies.",
            "Retrofit existing volumes by snapshot-and-copy with encryption or workload migration plans.",
        )
        return (
            "failed",
            {"regions_without_default_encryption": explicit_false, **pb},
            None,
            "EBS encryption by default is off in one or more sampled Regions.",
        )
    readable = [r for r in rows if r.get("ebs_encryption_by_default") is not None]
    if not readable:
        return ("unknown", {"samples": rows}, None, "Could not read EBS default encryption flags.")
    return ("passed", {"regions_confirmed": len(readable)}, None, "")


@register("ec2_ssh_open_to_world")
def ec2_ssh_open_to_world(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("ec2_ssh_world_exposure")
    if rows is None:
        wo = ev.get("ec2_world_open_ingress")
        if isinstance(wo, list):
            rows = [r for r in wo if r.get("matched_port") == 22]
        else:
            rows = None
    if rows is None:
        return ("unknown", {}, None, "Security group SSH exposure scan unavailable.")
    if len(rows) == 0:
        return ("passed", {"rules_evaluated": "ssh_world_sample"}, None, "")
    pb = _playbook(
        "Remove 0.0.0.0/0 and ::/0 ingress on TCP/22; use AWS Systems Manager Session Manager, EC2 Instance Connect, or VPN-based bastions.",
        "Scope SSH to corporate prefixes via managed prefix lists; break-glass access via temporary security-group rules with approval workflow.",
        "Enable VPC Flow Logs and GuardDuty to detect brute-force patterns while you tighten ingress.",
    )
    sample = rows[:25]
    return (
        "failed",
        {"open_ssh_security_groups": sample, "total_observed": len(rows), **pb},
        None,
        "Security groups allow SSH from the Internet — restrict ingress and prefer Session Manager.",
    )


@register("ec2_non_ssh_sensitive_ports_world_open")
def ec2_non_ssh_sensitive_ports_world_open(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("ec2_world_open_ingress")
    if rows is None:
        return ("unknown", {}, None, "Security group Internet exposure scan unavailable.")
    bad = [r for r in rows if r.get("matched_port") != 22]
    if not bad:
        return ("passed", {"world_open_rules_checked": len(rows)}, None, "")
    return (
        "failed",
        {"non_ssh_world_open": bad[:45], "total_observed": len(bad)},
        None,
        "Restrict Internet ingress on database, RDP, Redis, and other sensitive ports; use bastions or private connectivity.",
    )


@register("ec2_sg_wide_port_ranges_world_open")
def ec2_sg_wide_port_ranges_world_open(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("ec2_sg_wide_port_ranges_world")
    if rows is None:
        return ("unknown", {}, None, "Wide EC2 security-group port scan unavailable.")
    if not rows:
        return ("passed", {"wide_range_findings": 0}, None, "")
    return (
        "failed",
        {"wide_tcp_ranges_open_to_world": rows[:35]},
        None,
        "Avoid large TCP port ranges opened to 0.0.0.0/0 — split rules and scope sources.",
    )


@register("ec2_launch_wizard_security_groups_avoid")
def ec2_launch_wizard_security_groups_avoid(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("ec2_launch_wizard_security_groups")
    if rows is None:
        return ("unknown", {}, None, "Security group naming inventory unavailable.")
    if not rows:
        return ("passed", {"launch_wizard_groups": 0}, None, "")
    return (
        "failed",
        {"launch_wizard_named_security_groups": rows[:40]},
        None,
        "Replace default launch-wizard-* security groups with explicitly named, least-privilege groups.",
    )


@register("ec2_security_group_high_rule_count")
def ec2_security_group_high_rule_count(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("ec2_security_groups_high_rule_count")
    if rows is None:
        return ("unknown", {}, None, "Security group rule counts unavailable.")
    if not rows:
        return ("passed", {"groups_over_threshold": 0}, None, "")
    return (
        "failed",
        {"security_groups_with_many_rules": rows[:35]},
        None,
        "Reduce overly large security groups — prefer prefix lists, consolidated policies, and periodic cleanup.",
    )


@register("ec2_security_groups_region_count_review")
def ec2_security_groups_region_count_review(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("ec2_security_group_counts_by_region")
    if rows is None:
        return ("unknown", {}, None, "Regional security group counts unavailable.")
    bad = [r for r in rows if int(r.get("security_group_count") or 0) > 250]
    if not bad:
        return ("passed", {"regions_checked": len(rows)}, None, "")
    return (
        "failed",
        {"regions_with_high_sg_count": bad},
        None,
        "High security-group counts increase drift risk — archive unused VPCs and consolidate groups.",
    )


@register("ec2_instance_profile_attached")
def ec2_instance_profile_attached(ev: dict[str, Any]) -> RuleEvalResult:
    post = ev.get("ec2_instance_posture")
    if post is None:
        return ("unknown", {}, None, "EC2 instance posture unavailable.")
    bad = [r for r in post if r.get("missing_iam_instance_profile")]
    if not bad:
        return ("passed", {"instances_checked": len(post)}, None, "")
    return (
        "failed",
        {"instances_without_instance_profile": bad[:40]},
        None,
        "Attach IAM instance profiles so workloads use temporary credentials instead of long-lived keys.",
    )


@register("ec2_instances_no_public_ipv4")
def ec2_instances_no_public_ipv4(ev: dict[str, Any]) -> RuleEvalResult:
    post = ev.get("ec2_instance_posture")
    if post is None:
        return ("unknown", {}, None, "EC2 instance posture unavailable.")
    bad = [r for r in post if r.get("has_public_ip")]
    if not bad:
        return ("passed", {"instances_checked": len(post)}, None, "")
    return (
        "failed",
        {"instances_with_public_ipv4_or_eip_assoc": bad[:40]},
        None,
        "Prefer private subnets with egress via NAT or VPC endpoints; avoid public IPv4 where possible.",
    )


@register("ec2_instances_public_subnet_public_ip")
def ec2_instances_public_subnet_public_ip(ev: dict[str, Any]) -> RuleEvalResult:
    post = ev.get("ec2_instance_posture")
    if post is None:
        return ("unknown", {}, None, "EC2 instance posture unavailable.")
    bad = [
        r
        for r in post
        if r.get("has_public_ip") and r.get("subnet_associates_with_igw_route") is True
    ]
    if not bad:
        return ("passed", {"instances_checked": len(post)}, None, "")
    return (
        "failed",
        {"instances_public_subnet_and_public_address": bad[:35]},
        None,
        "Instances in Internet-routed subnets with public addresses expand attack surface — use load balancers or private tiers.",
    )


@register("ec2_instances_avoid_default_security_group")
def ec2_instances_avoid_default_security_group(ev: dict[str, Any]) -> RuleEvalResult:
    post = ev.get("ec2_instance_posture")
    if post is None:
        return ("unknown", {}, None, "EC2 instance posture unavailable.")
    bad = [r for r in post if r.get("uses_default_security_group")]
    if not bad:
        return ("passed", {"instances_checked": len(post)}, None, "")
    return (
        "failed",
        {"instances_using_default_sg": bad[:40]},
        None,
        "Do not attach the VPC default security group to instances; create explicit workload groups.",
    )


@register("ec2_running_instances_termination_protection")
def ec2_running_instances_termination_protection(ev: dict[str, Any]) -> RuleEvalResult:
    post = ev.get("ec2_instance_posture")
    if post is None:
        return ("unknown", {}, None, "EC2 instance posture unavailable.")
    bad = [
        r
        for r in post
        if (r.get("state") or "").lower() == "running" and r.get("disable_api_termination") is False
    ]
    if not bad:
        return ("passed", {"running_checked": len([p for p in post if p.get("state") == "running"])}, None, "")
    return (
        "failed",
        {"running_instances_without_termination_protection": bad[:35]},
        None,
        "Enable termination protection for long-lived instances outside Auto Scaling groups.",
    )


@register("ec2_detailed_monitoring_enabled")
def ec2_detailed_monitoring_enabled(ev: dict[str, Any]) -> RuleEvalResult:
    post = ev.get("ec2_instance_posture")
    if post is None:
        return ("unknown", {}, None, "EC2 instance posture unavailable.")
    bad = [
        r for r in post if str(r.get("monitoring_state") or "").lower() not in ("enabled",)
    ]
    if not bad:
        return ("passed", {"instances_checked": len(post)}, None, "")
    return (
        "failed",
        {"instances_without_detailed_monitoring": bad[:40]},
        None,
        "Enable EC2 detailed monitoring for instances that need granular CloudWatch metrics.",
    )


@register("ec2_no_scheduled_retirement_events")
def ec2_no_scheduled_retirement_events(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("ec2_scheduled_instance_events")
    if rows is None:
        return ("unknown", {}, None, "EC2 scheduled event scan unavailable.")
    if not rows:
        return ("passed", {"instances_with_events": 0}, None, "")
    return (
        "failed",
        {"instances_with_scheduled_events": rows[:35]},
        None,
        "Resolve EC2 scheduled events (maintenance/retirement) via stop/start, migration, or AWS guidance.",
    )


@register("ec2_owned_ami_root_volume_encrypted")
def ec2_owned_ami_root_volume_encrypted(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("ec2_owned_ami_posture")
    if rows is None:
        return ("unknown", {}, None, "Owned AMI encryption metadata unavailable.")
    if not rows:
        return ("passed", {"owned_amis_checked": 0}, None, "")
    bad = [r for r in rows if r.get("root_encrypted") is not True]
    if not bad:
        return ("passed", {"owned_amis_checked": len(rows)}, None, "")
    return (
        "failed",
        {"amis_without_root_encryption": bad[:30]},
        None,
        "Encrypt AMIs at rest (root volume / snapshot encryption) before sharing or baking golden images.",
    )


@register("ec2_owned_ami_not_publicly_shared")
def ec2_owned_ami_not_publicly_shared(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("ec2_owned_ami_posture")
    if rows is None:
        return ("unknown", {}, None, "AMI launch-permission scan unavailable.")
    bad = [r for r in rows if r.get("public_launch_permission")]
    if not bad:
        return ("passed", {"owned_amis_checked": len(rows)}, None, "")
    return (
        "failed",
        {"amis_with_public_launch_permissions": bad[:25]},
        None,
        "Remove public AMI launch permissions — share only to trusted accounts.",
    )


@register("ec2_instances_single_primary_eni_expected")
def ec2_instances_single_primary_eni_expected(ev: dict[str, Any]) -> RuleEvalResult:
    post = ev.get("ec2_instance_posture")
    if post is None:
        return ("unknown", {}, None, "EC2 instance posture unavailable.")
    bad = [r for r in post if int(r.get("network_interface_count") or 0) > 1]
    if not bad:
        return ("passed", {"instances_checked": len(post)}, None, "")
    return (
        "failed",
        {"instances_with_multiple_enis": bad[:35]},
        None,
        "Review instances with multiple ENIs — ensure multi-homed design is intentional and documented.",
    )


@register("ec2_instances_modern_instance_family")
def ec2_instances_modern_instance_family(ev: dict[str, Any]) -> RuleEvalResult:
    post = ev.get("ec2_instance_posture")
    if post is None:
        return ("unknown", {}, None, "EC2 instance posture unavailable.")
    bad = [r for r in post if _ec2_instance_type_legacy(str(r.get("instance_type") or ""))]
    if not bad:
        return ("passed", {"instances_checked": len(post)}, None, "")
    return (
        "failed",
        {"instances_on_legacy_families": bad[:35]},
        None,
        "Migrate off legacy EC2 families for better price-performance and patch support.",
    )


@register("ec2_instances_launch_age_review")
def ec2_instances_launch_age_review(ev: dict[str, Any]) -> RuleEvalResult:
    post = ev.get("ec2_instance_posture")
    if post is None:
        return ("unknown", {}, None, "EC2 instance posture unavailable.")
    bad: list[dict[str, Any]] = []
    for r in post:
        age = _days_since(r.get("launch_time"))
        if age is not None and age > 730:
            row = dict(r)
            row["approx_age_days"] = age
            bad.append(row)
    if not bad:
        return ("passed", {"instances_checked": len(post)}, None, "")
    return (
        "failed",
        {"instances_launched_over_730_days_ago": bad[:35]},
        None,
        "Refresh long-lived instances via golden AMI pipelines or managed fleet upgrades.",
    )


@register("ec2_reserved_instances_expiring_review")
def ec2_reserved_instances_expiring_review(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("ec2_reserved_instances_expiring")
    if rows is None:
        return ("unknown", {}, None, "Reserved Instance expiration data unavailable.")
    if not rows:
        return ("passed", {"expiring_reservations": 0}, None, "")
    return (
        "failed",
        {"reserved_instances_expiring_soon": rows[:30]},
        None,
        "Renew or replace EC2 Reserved Instances before expiration to avoid on-demand price shocks.",
    )


@register("ec2_unused_key_pairs_cleanup")
def ec2_unused_key_pairs_cleanup(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("ec2_unused_key_pairs_by_region")
    if rows is None:
        return ("unknown", {}, None, "EC2 key pair inventory unavailable.")
    bad = [r for r in rows if int(r.get("unused_count") or 0) > 0]
    if not bad:
        return ("passed", {"regions_with_unused_keys": 0}, None, "")
    return (
        "failed",
        {"regions_with_unused_key_pairs": bad[:15]},
        None,
        "Delete unused EC2 key pairs after migrating to SSM or instance roles.",
    )


@register("ec2_unattached_enis_cleanup")
def ec2_unattached_enis_cleanup(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("ec2_unattached_network_interfaces")
    if rows is None:
        return ("unknown", {}, None, "Unattached ENI inventory unavailable.")
    if not rows:
        return ("passed", {"unattached_enis": 0}, None, "")
    return (
        "failed",
        {"unattached_network_interfaces": rows[:35]},
        None,
        "Delete unattached ENIs to avoid stray configuration and accidental attachment.",
    )


@register("ec2_account_instance_limit_headroom")
def ec2_account_instance_limit_headroom(ev: dict[str, Any]) -> RuleEvalResult:
    ratio = ev.get("ec2_instance_inventory_vs_limit_ratio")
    max_i = ev.get("ec2_account_max_instances")
    inv = ev.get("ec2_instance_inventory_count")
    if ratio is None or max_i is None:
        return ("unknown", {}, None, "Account EC2 limit ratio unavailable.")
    if ratio <= 0.85:
        return ("passed", {"inventory": inv, "max_instances": max_i, "ratio": round(ratio, 3)}, None, "")
    return (
        "failed",
        {"inventory": inv, "max_instances": max_i, "ratio": round(ratio, 3)},
        None,
        "EC2 instance inventory is close to the account limit — request a limit increase or rebalance Regions.",
    )


@register("rds_no_public_unencrypted")
def rds_no_public_unencrypted(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("rds_instances_posture")
    if rows is None:
        return ("unknown", {}, None, "RDS posture data unavailable.")
    bad = [
        r
        for r in rows
        if bool(r.get("publicly_accessible")) or not bool(r.get("storage_encrypted"))
    ]
    if not bad:
        return ("passed", {"instances_checked": len(rows)}, None, "")
    pb = _playbook(
        "Disable PubliclyAccessible on RDS; place databases in private subnets with security groups scoped to application tiers.",
        "Enable storage encryption at creation (use KMS CMKs for regulated workloads); plan migration for legacy unencrypted instances.",
        "Enforce with AWS Config rules and SCP guardrails; rotate credentials via Secrets Manager.",
    )
    return (
        "failed",
        {"non_compliant_instances": bad[:30], **pb},
        None,
        "One or more RDS instances are Internet-accessible or lack storage encryption.",
    )


@register("iam_no_administrator_access_users")
def iam_no_administrator_access_users(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("iam_users_with_administrator_access")
    if rows is None:
        return ("unknown", {}, None, "Could not enumerate attached policies for IAM users.")
    if len(rows) == 0:
        return ("passed", {"users_checked": "attached_policies_sample"}, None, "")
    pb = _playbook(
        "Replace AdministratorAccess on IAM users with job-function policies or permission sets via IAM Identity Center (SSO).",
        "Introduce approval-based elevation (break-glass roles + MFA + CloudTrail alerts on AssumeRole).",
        "Use IAM Access Analyzer and periodic credential reports to remove unused admin-equivalent grants.",
    )
    return (
        "failed",
        {"users_with_administrator_access": rows[:40], **pb},
        None,
        "IAM users still attach AWS managed AdministratorAccess — migrate to least privilege.",
    )


@register("cloudtrail_multiregion_logging")
def cloudtrail_multiregion_logging(ev: dict[str, Any]) -> RuleEvalResult:
    trails = ev.get("cloudtrail_trails") or []
    if not trails:
        return ("unknown", {}, None, "CloudTrail metadata unavailable.")
    ok = [t for t in trails if t.get("is_multi_region") is True and t.get("is_logging") is True]
    if ok:
        return ("passed", {"multiregion_logging_trails": len(ok)}, None, "")
    pb = _playbook(
        "Create or update an organizational trail with multi-Region logging and management events.",
        "Deliver logs to a dedicated audit S3 bucket with MFA delete, KMS encryption, and strict bucket policies.",
        "Integrate with CloudWatch Logs for alarming on sensitive API calls.",
    )
    return (
        "failed",
        {"trails": trails, **pb},
        None,
        "No multi-Region CloudTrail with active logging was detected in sampled trails.",
    )


@register("cloudtrail_log_file_validation")
def cloudtrail_log_file_validation(ev: dict[str, Any]) -> RuleEvalResult:
    trails = ev.get("cloudtrail_trails") or []
    logging_trails = [t for t in trails if t.get("is_logging") is True]
    if not trails:
        return ("unknown", {}, None, "CloudTrail metadata unavailable.")
    if not logging_trails:
        return ("unknown", {"note": "no_logging_trail"}, None, "Cannot evaluate log file validation without an active trail.")
    missing = [t for t in logging_trails if not t.get("log_file_validation_enabled")]
    if not missing:
        return ("passed", {"logging_trails_validated": len(logging_trails)}, None, "")
    pb = _playbook(
        "Enable log file validation on each active trail to detect tampering.",
        "Protect the S3 bucket with versioning, MFA delete, SSE-KMS, and bucket policies denying insecure transport.",
        "Forward copies of logs to a separate security account using Organizations trails.",
    )
    return (
        "failed",
        {"trails_missing_validation": missing[:15], **pb},
        None,
        "Active CloudTrail trails should enable log file validation.",
    )


@register("cost_unassociated_elastic_ips")
def cost_unassociated_elastic_ips(ev: dict[str, Any]) -> RuleEvalResult:
    sig = ev.get("ec2_cost_signals")
    if sig is None:
        return ("unknown", {}, None, "Elastic IP inventory unavailable.")
    summary = sig.get("summary") or {}
    n = int(summary.get("unassociated_elastic_ip_count") or 0)
    if n <= 0:
        return ("passed", {"unassociated_elastic_ip_count": 0}, None, "")
    pb = _playbook(
        "Release unattached Elastic IPs or associate them with NLBs/EC2 as needed — AWS bills hourly for allocated-but-unassociated IPv4 addresses in commercial Regions.",
        "Automate detection with Trusted Advisor / Compute Optimizer reports and IaC drift checks.",
        "Use VPC endpoints and DNS-based ingress patterns to reduce reliance on static public IPs.",
    )
    return (
        "failed",
        {
            "unassociated_elastic_ips": (sig.get("unassociated_elastic_ips") or [])[:25],
            "unassociated_elastic_ip_count": n,
            **pb,
        },
        None,
        "Unassociated Elastic IPs incur ongoing charges — release or attach them.",
    )


@register("cost_unattached_ebs_volumes")
def cost_unattached_ebs_volumes(ev: dict[str, Any]) -> RuleEvalResult:
    sig = ev.get("ec2_cost_signals")
    if sig is None:
        return ("unknown", {}, None, "EBS volume inventory unavailable.")
    summary = sig.get("summary") or {}
    n = int(summary.get("unattached_volume_count") or 0)
    gb = int(summary.get("unattached_volume_size_gb") or 0)
    if n <= 0:
        return ("passed", {"unattached_volume_count": 0}, None, "")
    pb = _playbook(
        "Snapshot retained volumes if needed, then delete orphaned `available` volumes; Tag Editor / Resource Groups helps ownership.",
        "Prevent drift with IaC ownership tags and automated janitor lambdas with approve-before-delete workflows.",
        "Right-size volumes during reattachment and consider gp3 for price/performance.",
    )
    return (
        "failed",
        {
            "unattached_volumes": (sig.get("unattached_ebs_volumes") or [])[:30],
            "unattached_volume_count": n,
            "unattached_volume_size_gb": gb,
            **pb,
        },
        None,
        "Detached EBS volumes continue to incur monthly GB-month charges.",
    )


@register("cost_stopped_ec2_fleet_review")
def cost_stopped_ec2_fleet_review(ev: dict[str, Any]) -> RuleEvalResult:
    sig = ev.get("ec2_cost_signals")
    if sig is None:
        return ("unknown", {}, None, "Stopped EC2 inventory unavailable.")
    summary = sig.get("summary") or {}
    n = int(summary.get("stopped_instance_count") or 0)
    if n <= 5:
        return ("passed", {"stopped_instance_count": n}, None, "")
    pb = _playbook(
        "For stopped instances you no longer need, terminate after snapshots/AMIs are captured to eliminate attached EBS costs.",
        "Use Instance Scheduler or AWS Compute Optimizer rightsizing recommendations for cyclical workloads.",
        "Archive rarely used environments to smaller instance families or migrate to Graviton where applicable.",
    )
    return (
        "failed",
        {
            "stopped_instances_sample": (sig.get("stopped_ec2_instances") or [])[:25],
            "stopped_instance_count": n,
            **pb,
        },
        None,
        "Large fleets of stopped EC2 instances usually indicate lingering EBS and licensing costs — review and decommission.",
    )


@register("access_analyzer_enabled_check")
def access_analyzer_enabled_check(ev: dict[str, Any]) -> RuleEvalResult:
    n = ev.get("access_analyzer_active_count")
    if n is None:
        return ("unknown", {}, None, "Could not list IAM Access Analyzer in the sampled Region.")
    if int(n) >= 1:
        return ("passed", {"active_analyzers": int(n)}, None, "")
    return (
        "failed",
        {"active_analyzers": 0},
        None,
        "Enable IAM Access Analyzer (account or organization scope) to detect unintended resource access paths.",
    )


@register("iam_users_have_group_membership")
def iam_users_have_group_membership(ev: dict[str, Any]) -> RuleEvalResult:
    missing = ev.get("iam_users_without_groups")
    if missing is None:
        return ("unknown", {}, None, "IAM group membership data not collected.")
    if len(missing) == 0:
        return ("passed", {"users_without_groups": 0}, None, "")
    return (
        "failed",
        {"users_without_groups": missing[:60], "total": len(missing)},
        None,
        "Attach IAM users to groups for structured permissions (Trend: IAM user group membership).",
    )


@register("iam_groups_avoid_inline_policies")
def iam_groups_avoid_inline_policies(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("iam_groups_with_inline_policies")
    if rows is None:
        return ("unknown", {}, None, "IAM inline group policy inventory unavailable.")
    if len(rows) == 0:
        return ("passed", {"groups_with_inline": 0}, None, "")
    return (
        "failed",
        {"groups": rows[:35]},
        None,
        "Replace IAM group inline policies with managed policies attached to the group.",
    )


@register("iam_no_compromised_key_quarantine")
def iam_no_compromised_key_quarantine(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("iam_users_compromised_key_quarantine")
    if rows is None:
        return ("unknown", {}, None, "Could not scan attached policies for compromise quarantine markers.")
    if len(rows) == 0:
        return ("passed", {"flagged_users": 0}, None, "")
    return (
        "failed",
        {"users_with_quarantine_policy": rows[:40]},
        None,
        "Rotate and remove compromised IAM keys; AWSCompromisedKeyQuarantine policies indicate active response.",
    )


@register("iam_root_mfa_enabled")
def iam_root_mfa_enabled(ev: dict[str, Any]) -> RuleEvalResult:
    ca = ev.get("iam_credential_analysis") or {}
    active = ca.get("root_mfa_active")
    if active is None:
        return ("unknown", {}, None, "Root MFA status unavailable from credential report.")
    if active is True:
        return ("passed", {"root_mfa_active": True}, None, "")
    return (
        "failed",
        {"root_mfa_active": False},
        None,
        "Enable MFA on the AWS account root user.",
    )


@register("iam_access_keys_under_max_age")
def iam_access_keys_under_max_age(ev: dict[str, Any]) -> RuleEvalResult:
    ca = ev.get("iam_credential_analysis") or {}
    stale = ca.get("access_keys_older_than_days") or []
    threshold = int(ca.get("threshold_days") or 90)
    if ev.get("iam_credential_report_csv") is None:
        return ("unknown", {}, None, "Credential report not available.")
    if not stale:
        return ("passed", {"stale_keys": 0, "threshold_days": threshold}, None, "")
    return (
        "failed",
        {"stale_keys": stale[:40], "threshold_days": threshold},
        None,
        f"Rotate IAM access keys older than {threshold} days.",
    )


@register("iam_single_active_access_key_per_user")
def iam_single_active_access_key_per_user(ev: dict[str, Any]) -> RuleEvalResult:
    ca = ev.get("iam_credential_analysis") or {}
    multi = ca.get("users_with_multiple_active_keys") or []
    if ev.get("iam_credential_report_csv") is None:
        return ("unknown", {}, None, "Credential report not available.")
    if len(multi) == 0:
        return ("passed", {"users_with_two_active_keys": 0}, None, "")
    return (
        "failed",
        {"users": multi[:50]},
        None,
        "Limit IAM users to one active access key pair unless a documented exception exists.",
    )


@register("iam_avoid_password_and_long_term_keys")
def iam_avoid_password_and_long_term_keys(ev: dict[str, Any]) -> RuleEvalResult:
    ca = ev.get("iam_credential_analysis") or {}
    both = ca.get("users_with_password_and_active_key") or []
    if ev.get("iam_credential_report_csv") is None:
        return ("unknown", {}, None, "Credential report not available.")
    if len(both) == 0:
        return ("passed", {"users": 0}, None, "")
    return (
        "failed",
        {"users_with_console_and_keys": both[:50]},
        None,
        "Prefer separate principals for console vs programmatic access (avoid password + access keys on same IAM user).",
    )


@register("iam_password_policy_strong")
def iam_password_policy_strong(ev: dict[str, Any]) -> RuleEvalResult:
    pol = ev.get("iam_password_policy")
    if pol is None:
        return ("failed", {}, None, "Set an IAM password policy before evaluating strength.")
    issues: list[str] = []
    if int(pol.get("MinimumPasswordLength") or 0) < 14:
        issues.append("minimum_length_lt_14")
    if pol.get("RequireSymbols") is not True:
        issues.append("symbols_not_required")
    if pol.get("RequireNumbers") is not True:
        issues.append("numbers_not_required")
    if pol.get("RequireUppercaseCharacters") is not True:
        issues.append("uppercase_not_required")
    if pol.get("RequireLowercaseCharacters") is not True:
        issues.append("lowercase_not_required")
    if issues:
        return (
            "failed",
            {"policy_issues": issues, "policy_snapshot": {k: pol.get(k) for k in sorted(pol.keys())[:12]}},
            None,
            "Strengthen IAM password policy (length ≥14, upper/lower/number/symbol requirements).",
        )
    return ("passed", {"checks": "baseline_strong_password_policy"}, None, "")


@register("iam_cross_account_trust_external_id")
def iam_cross_account_trust_external_id(ev: dict[str, Any]) -> RuleEvalResult:
    bad = ev.get("iam_cross_account_trust_without_external_id")
    if bad is None:
        return ("unknown", {}, None, "Cross-account role trust scan unavailable.")
    if len(bad) == 0:
        return ("passed", {"roles_flagged": 0}, None, "")
    return (
        "failed",
        {"roles_missing_external_id_condition": bad[:40]},
        None,
        "Cross-account IAM role trust policies should require sts:ExternalId (and MFA where applicable).",
    )


@register("iam_server_certificates_not_expiring_soon")
def iam_server_certificates_not_expiring_soon(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("iam_server_certificates")
    if rows is None:
        return ("unknown", {}, None, "IAM server certificate list unavailable.")
    if len(rows) == 0:
        return ("passed", {"certificates": 0}, None, "")
    warn: list[dict[str, Any]] = []
    expired: list[dict[str, Any]] = []
    for r in rows:
        days = r.get("days_to_expiry")
        if days is None:
            continue
        if days < 0:
            expired.append(r)
        elif days <= 30:
            warn.append(r)
    if expired:
        return (
            "failed",
            {"expired": expired[:20], "expiring_within_30d": warn[:20]},
            None,
            "Remove or rotate expired IAM server certificates.",
        )
    if warn:
        return (
            "failed",
            {"expiring_within_30d": warn[:25]},
            None,
            "Renew IAM SSL/TLS server certificates before they expire.",
        )
    return ("passed", {"certificates_checked": len(rows)}, None, "")


@register("iam_no_unused_empty_groups")
def iam_no_unused_empty_groups(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("iam_unused_groups")
    if rows is None:
        return ("unknown", {}, None, "Unused IAM group inventory unavailable.")
    if len(rows) == 0:
        return ("passed", {"unused_groups": 0}, None, "")
    return (
        "failed",
        {"unused_groups": rows[:40]},
        None,
        "Remove or populate IAM groups with zero members.",
    )


@register("lambda_function_url_requires_iam_auth")
def lambda_function_url_requires_iam_auth(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("lambda_functions_posture")
    if rows is None:
        return ("unknown", {}, None, "Lambda inventory unavailable.")
    bad = [
        r
        for r in rows
        if r.get("has_function_url") and (r.get("function_url_auth_type") or "") != "AWS_IAM"
    ]
    if not bad:
        return ("passed", {"functions_checked": len(rows)}, None, "")
    return (
        "failed",
        {"function_urls_without_iam_auth": bad[:35]},
        None,
        "Use IAM authentication for Lambda function URLs or remove unused URLs.",
    )


@register("lambda_execution_role_present")
def lambda_execution_role_present(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("lambda_functions_posture")
    if rows is None:
        return ("unknown", {}, None, "Lambda inventory unavailable.")
    bad = [r for r in rows if not (r.get("role_arn") or "").strip()]
    if not bad:
        return ("passed", {"functions_checked": len(rows)}, None, "")
    return (
        "failed",
        {"functions_missing_execution_role": bad[:35]},
        None,
        "Assign an active IAM execution role to each Lambda function.",
    )


@register("lambda_dead_letter_configured")
def lambda_dead_letter_configured(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("lambda_functions_posture")
    if rows is None:
        return ("unknown", {}, None, "Lambda inventory unavailable.")
    bad = [
        r
        for r in rows
        if r.get("package_type") in (None, "Zip", "Image") and not (r.get("dead_letter_target_arn") or "").strip()
    ]
    if not bad:
        return ("passed", {"functions_checked": len(rows)}, None, "")
    return (
        "failed",
        {"functions_without_dlq": bad[:35]},
        None,
        "Configure a dead-letter queue or target for Lambda asynchronous failures.",
    )


@register("lambda_environment_encrypted_with_cmek")
def lambda_environment_encrypted_with_cmek(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("lambda_functions_posture")
    if rows is None:
        return ("unknown", {}, None, "Lambda inventory unavailable.")
    bad = [
        r
        for r in rows
        if int(r.get("environment_variable_count") or 0) > 0 and not (r.get("kms_key_arn") or "").strip()
    ]
    if not bad:
        return ("passed", {"functions_checked": len(rows)}, None, "")
    return (
        "failed",
        {"functions_env_without_cmek": bad[:30]},
        None,
        "Encrypt Lambda environment variables at rest using a customer-managed KMS key.",
    )


@register("lambda_tracing_active")
def lambda_tracing_active(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("lambda_functions_posture")
    if rows is None:
        return ("unknown", {}, None, "Lambda inventory unavailable.")
    bad = [r for r in rows if (r.get("tracing_mode") or "").strip().upper() != "ACTIVE"]
    if not bad:
        return ("passed", {"functions_checked": len(rows)}, None, "")
    return (
        "failed",
        {"functions_without_active_tracing": bad[:35]},
        None,
        "Enable active AWS X-Ray tracing on Lambda functions that handle production traffic.",
    )


@register("lambda_supported_runtime")
def lambda_supported_runtime(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("lambda_functions_posture")
    if rows is None:
        return ("unknown", {}, None, "Lambda inventory unavailable.")
    bad: list[dict[str, Any]] = []
    for r in rows:
        rt = (r.get("runtime") or "").strip()
        pkg = r.get("package_type") or "Zip"
        if pkg == "Image":
            continue
        if not rt or rt in _DEPRECATED_LAMBDA_RUNTIMES:
            bad.append(r)
    if not bad:
        return ("passed", {"functions_checked": len(rows)}, None, "")
    return (
        "failed",
        {"functions_unsupported_or_legacy_runtime": bad[:35]},
        None,
        "Upgrade Lambda functions to a currently supported runtime.",
    )


@register("lambda_execution_role_no_inline_policies")
def lambda_execution_role_no_inline_policies(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("lambda_functions_posture")
    if rows is None:
        return ("unknown", {}, None, "Lambda inventory unavailable.")
    bad = [r for r in rows if int(r.get("execution_role_inline_policy_count") or 0) > 0]
    if not bad:
        return ("passed", {"functions_checked": len(rows)}, None, "")
    return (
        "failed",
        {"functions_roles_with_inline_policies": bad[:35]},
        None,
        "Replace inline policies on Lambda execution roles with customer- or AWS-managed policies.",
    )


@register("lambda_execution_role_no_admin_access")
def lambda_execution_role_no_admin_access(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("lambda_functions_posture")
    if rows is None:
        return ("unknown", {}, None, "Lambda inventory unavailable.")
    bad = [r for r in rows if r.get("execution_role_has_administrator_access")]
    if not bad:
        return ("passed", {"functions_checked": len(rows)}, None, "")
    return (
        "failed",
        {"functions_with_admin_execution_role": bad[:25]},
        None,
        "Remove AdministratorAccess from Lambda execution roles; scope to least privilege.",
    )


@register("lambda_code_signing_enabled_zip")
def lambda_code_signing_enabled_zip(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("lambda_functions_posture")
    if rows is None:
        return ("unknown", {}, None, "Lambda inventory unavailable.")
    bad = [
        r
        for r in rows
        if (r.get("package_type") or "Zip") == "Zip" and not (r.get("code_signing_config_arn") or "").strip()
    ]
    if not bad:
        return ("passed", {"functions_checked": len(rows)}, None, "")
    return (
        "failed",
        {"functions_zip_without_code_signing": bad[:30]},
        None,
        "Enable Lambda code signing for ZIP-deployed functions.",
    )


@register("s3_bucket_default_encryption_enabled")
def s3_bucket_default_encryption_enabled(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("s3_buckets")
    if rows is None:
        return ("unknown", {}, None, "S3 bucket inventory unavailable.")
    bad = [r for r in rows if r.get("default_encryption_enabled") is not True]
    if not bad:
        return ("passed", {"buckets_checked": len(rows)}, None, "")
    return (
        "failed",
        {"buckets_without_default_encryption": bad[:40]},
        None,
        "Enable default encryption (SSE-S3 or SSE-KMS) on every S3 bucket.",
    )


@register("s3_bucket_versioning_enabled")
def s3_bucket_versioning_enabled(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("s3_buckets")
    if rows is None:
        return ("unknown", {}, None, "S3 bucket inventory unavailable.")
    bad = [r for r in rows if (r.get("versioning_status") or "") != "Enabled"]
    if not bad:
        return ("passed", {"buckets_checked": len(rows)}, None, "")
    return (
        "failed",
        {"buckets_without_versioning": bad[:40]},
        None,
        "Enable versioning on buckets that store critical or regulated data.",
    )


@register("s3_bucket_policy_denies_insecure_transport")
def s3_bucket_policy_denies_insecure_transport(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("s3_buckets")
    if rows is None:
        return ("unknown", {}, None, "S3 bucket inventory unavailable.")
    bad = [
        r
        for r in rows
        if r.get("bucket_policy_present") is True and r.get("bucket_policy_denies_insecure_transport") is not True
    ]
    if not bad:
        return ("passed", {"buckets_checked": len(rows)}, None, "")
    return (
        "failed",
        {"buckets_policy_missing_secure_transport_deny": bad[:35]},
        None,
        "Add a bucket policy deny for aws:SecureTransport=false to enforce HTTPS-only access.",
    )


@register("ec2_imdsv2_required")
def ec2_imdsv2_required(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("ec2_instance_imds_posture")
    if rows is None:
        return ("unknown", {}, None, "EC2 instance metadata inventory unavailable.")
    bad = []
    for r in rows:
        endpoint = (r.get("http_endpoint") or "").lower()
        tokens = (r.get("http_tokens") or "").lower()
        if endpoint == "disabled":
            continue
        if tokens != "required":
            bad.append(r)
    if not bad:
        return ("passed", {"instances_checked": len(rows)}, None, "")
    return (
        "failed",
        {"instances_without_imdsv2_required": bad[:50]},
        None,
        "Require IMDSv2 (HttpTokens=required) on EC2 instances.",
    )


@register("ecs_container_insights_enabled")
def ecs_container_insights_enabled(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("ecs_clusters_posture")
    if rows is None:
        return ("unknown", {}, None, "ECS cluster inventory unavailable.")
    if len(rows) == 0:
        return ("passed", {"clusters_checked": 0}, None, "")
    bad = [r for r in rows if (r.get("container_insights") or "").lower() != "enabled"]
    if not bad:
        return ("passed", {"clusters_checked": len(rows)}, None, "")
    return (
        "failed",
        {"clusters_without_container_insights": bad[:30]},
        None,
        "Enable CloudWatch Container Insights on production ECS clusters.",
    )


@register("ssm_managed_ec2_coverage")
def ssm_managed_ec2_coverage(ev: dict[str, Any]) -> RuleEvalResult:
    ec2_n = ev.get("ec2_instance_inventory_count")
    ssm_n = ev.get("ssm_managed_instance_count")
    if ec2_n is None or ssm_n is None:
        return ("unknown", {}, None, "EC2 or SSM inventory unavailable.")
    if ec2_n < 5:
        return ("passed", {"ec2_instances_counted": ec2_n, "ssm_managed_instances": ssm_n}, None, "")
    if ssm_n == 0:
        return (
            "failed",
            {"ec2_instances_counted": ec2_n, "ssm_managed_instances": ssm_n},
            None,
            "Register EC2 instances with AWS Systems Manager Session Manager / fleet management.",
        )
    return ("passed", {"ec2_instances_counted": ec2_n, "ssm_managed_instances": ssm_n}, None, "")


@register("secrets_manager_rotation_enabled")
def secrets_manager_rotation_enabled(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("secrets_manager_posture")
    if rows is None:
        return ("unknown", {}, None, "Secrets Manager inventory unavailable.")
    if len(rows) == 0:
        return ("passed", {"secrets_checked": 0}, None, "")
    bad = [r for r in rows if not r.get("rotation_enabled")]
    if not bad:
        return ("passed", {"secrets_checked": len(rows)}, None, "")
    return (
        "failed",
        {"secrets_without_rotation": bad[:35]},
        None,
        "Enable automatic rotation for Secrets Manager secrets where supported.",
    )


@register("secrets_manager_customer_kms_key")
def secrets_manager_customer_kms_key(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("secrets_manager_posture")
    if rows is None:
        return ("unknown", {}, None, "Secrets Manager inventory unavailable.")
    if len(rows) == 0:
        return ("passed", {"secrets_checked": 0}, None, "")

    def _default_sm_key(kid: str) -> bool:
        k = (kid or "").strip().lower()
        return not k or "alias/aws/secretsmanager" in k

    bad = [r for r in rows if _default_sm_key(str(r.get("kms_key_id") or ""))]
    if not bad:
        return ("passed", {"secrets_checked": len(rows)}, None, "")
    return (
        "failed",
        {"secrets_using_default_kms": bad[:35]},
        None,
        "Encrypt Secrets Manager secrets with a customer-managed KMS CMK.",
    )


@register("s3_lifecycle_configuration_present")
def s3_lifecycle_configuration_present(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("s3_buckets")
    if rows is None:
        return ("unknown", {}, None, "S3 bucket inventory unavailable.")
    missing = [r for r in rows if r.get("lifecycle_configured") is not True]
    if not missing:
        return ("passed", {"buckets_checked": len(rows)}, None, "")
    return (
        "failed",
        {"buckets_without_lifecycle": missing[:40]},
        None,
        "Add S3 lifecycle rules to transition or expire stale objects and reduce storage cost.",
    )


@register("lambda_provisioned_concurrency_cost_review")
def lambda_provisioned_concurrency_cost_review(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("lambda_functions_posture")
    if rows is None:
        return ("unknown", {}, None, "Lambda inventory unavailable.")
    flagged = [r for r in rows if int(r.get("provisioned_concurrency_units") or 0) > 0]
    if not flagged:
        return ("passed", {"functions_checked": len(rows), "provisioned_concurrency_allocations": 0}, None, "")
    return (
        "failed",
        {"functions_with_provisioned_concurrency": flagged[:30]},
        None,
        "Review provisioned concurrency allocations — they add fixed cost; right-size or remove if unused.",
    )


@register("cost_zero_spend_signal")
def cost_zero_spend_signal(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("cost_by_service_30d") or []
    total = sum(r.get("amount", 0) for r in rows)
    if total == 0 and rows:
        return ("passed", {"note": "zero_spend", "total": 0}, None, "Informational: zero reported spend in window.")
    return ("passed", {"total": total}, None, "")


def _call_evaluator(
    fn: Callable[..., RuleEvalResult],
    evidence: dict[str, Any],
    rule: dict[str, Any],
) -> RuleEvalResult:
    """Invoke legacy 1-arg evaluators or newer 2-arg (evidence, rule) evaluators."""
    try:
        sig = inspect.signature(fn)
        if len(sig.parameters) >= 2:
            return fn(evidence, rule)  # type: ignore[misc]
    except (TypeError, ValueError):
        pass
    return fn(evidence)  # type: ignore[misc]


@register("cspm_signal")
def cspm_signal(ev: dict[str, Any], rule: dict[str, Any]) -> RuleEvalResult:
    """Evaluate a precomputed CSPM signal from `merged_evidence['cspm_signals']` (AUD-001)."""
    sid = (rule or {}).get("cspm_signal")
    if not sid:
        return ("unknown", {}, None, "Rule YAML must set `cspm_signal: SIGNAL_KEY`.")
    sigs = ev.get("cspm_signals")
    if sigs is None:
        return ("unknown", {"cspm_signal": sid}, None, "CSPM signals missing — run collector merge with an updated worker.")
    block = sigs.get(sid)
    if block is None:
        return ("unknown", {"cspm_signal": sid}, None, "Signal key not produced by collector.")
    st = block.get("status") or "unknown"
    rem = (block.get("remediation_hint") or block.get("remediation") or "").strip()
    evid = block.get("evidence") if isinstance(block.get("evidence"), dict) else {}
    rid = block.get("resource_id")
    if st == "passed":
        return ("passed", evid, rid, "")
    if st == "failed":
        return ("failed", evid, rid, rem or "Review evidence and align with AWS / Trend Micro CSPM guidance.")
    return ("unknown", evid, rid, rem or "")


def load_rule_definitions(pack_dir: Path) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for path in sorted(pack_dir.rglob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    rules.append(item)
        elif isinstance(raw, dict):
            rules.append(raw)
    return rules


def evaluate_all(
    evidence: dict[str, Any],
    pack_dir: Path,
    *,
    on_rule_progress: Callable[[int, int], None] | None = None,
    progress_every: int = 5,
) -> list[dict[str, Any]]:
    rules = load_rule_definitions(pack_dir)
    total = len(rules)
    if total == 0:
        logger.warning("No rule YAML files found under %s — checks will be empty.", pack_dir)

    def bump(done: int) -> None:
        if on_rule_progress is None:
            return
        if done == 0 or done == total or done % progress_every == 0:
            on_rule_progress(done, total)

    out: list[dict[str, Any]] = []
    bump(0)
    for i, rule in enumerate(rules, start=1):
        ev_name = rule["evaluator"]
        fn = EVALUATORS.get(ev_name)
        if not fn:
            out.append(
                {
                    "check_id": rule["id"],
                    "pillar": rule["pillar"],
                    "severity": rule["severity"],
                    "war_theme": rule.get("war_theme"),
                    "cis_control": resolve_cis_control(rule),
                    "status": "unknown",
                    "resource_id": None,
                    "evidence_json": {"error": f"unknown_evaluator:{ev_name}"},
                    "remediation_hint": "Register evaluator in rules_engine.py",
                }
            )
            bump(i)
            continue
        status, ev_subset, resource_id, hint = _call_evaluator(fn, evidence, rule)
        out.append(
            {
                "check_id": rule["id"],
                "pillar": rule["pillar"],
                "severity": rule["severity"],
                "war_theme": rule.get("war_theme"),
                "cis_control": resolve_cis_control(rule),
                "status": status,
                "resource_id": resource_id,
                "evidence_json": ev_subset,
                "remediation_hint": hint or None,
            }
        )
        bump(i)
    return out


def aggregate_counts(findings: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "total": len(findings),
        "by_severity": {},
        "by_pillar": {},
        "by_status": {},
        "groups": {},
        "failed_groups": {},
    }
    for f in findings:
        sev = f.get("severity", "unknown")
        summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
        pill = f.get("pillar", "unknown")
        summary["by_pillar"][pill] = summary["by_pillar"].get(pill, 0) + 1
        st = f.get("status", "unknown")
        summary["by_status"][st] = summary["by_status"].get(st, 0) + 1
        g = summary["groups"].setdefault(pill, {})
        g[sev] = g.get(sev, 0) + 1
        if st == "failed":
            fg = summary["failed_groups"].setdefault(pill, {})
            fg[sev] = fg.get(sev, 0) + 1
    return summary
