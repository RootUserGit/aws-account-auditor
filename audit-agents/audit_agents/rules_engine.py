from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

import yaml

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


@register("cost_zero_spend_signal")
def cost_zero_spend_signal(ev: dict[str, Any]) -> RuleEvalResult:
    rows = ev.get("cost_by_service_30d") or []
    total = sum(r.get("amount", 0) for r in rows)
    if total == 0 and rows:
        return ("passed", {"note": "zero_spend", "total": 0}, None, "Informational: zero reported spend in window.")
    return ("passed", {"total": total}, None, "")


def load_rule_definitions(pack_dir: Path) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for path in sorted(pack_dir.glob("*.yaml")):
        rules.append(yaml.safe_load(path.read_text()))
    return rules


def evaluate_all(evidence: dict[str, Any], pack_dir: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for rule in load_rule_definitions(pack_dir):
        ev_name = rule["evaluator"]
        fn = EVALUATORS.get(ev_name)
        if not fn:
            out.append(
                {
                    "check_id": rule["id"],
                    "pillar": rule["pillar"],
                    "severity": rule["severity"],
                    "war_theme": rule.get("war_theme"),
                    "status": "unknown",
                    "resource_id": None,
                    "evidence_json": {"error": f"unknown_evaluator:{ev_name}"},
                    "remediation_hint": "Register evaluator in rules_engine.py",
                }
            )
            continue
        status, ev_subset, resource_id, hint = fn(evidence)
        out.append(
            {
                "check_id": rule["id"],
                "pillar": rule["pillar"],
                "severity": rule["severity"],
                "war_theme": rule.get("war_theme"),
                "status": status,
                "resource_id": resource_id,
                "evidence_json": ev_subset,
                "remediation_hint": hint or None,
            }
        )
    return out


def aggregate_counts(findings: list[dict[str, Any]]) -> dict[str, Any]:
    summary = {"total": len(findings), "by_severity": {}, "by_pillar": {}, "by_status": {}}
    for f in findings:
        sev = f.get("severity", "unknown")
        summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
        pill = f.get("pillar", "unknown")
        summary["by_pillar"][pill] = summary["by_pillar"].get(pill, 0) + 1
        st = f.get("status", "unknown")
        summary["by_status"][st] = summary["by_status"].get(st, 0) + 1
    return summary
