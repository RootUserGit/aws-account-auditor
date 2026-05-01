from __future__ import annotations

from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

from audit_data_collection.types import CollectorResult


def collect_cost(session: boto3.Session) -> CollectorResult:
    out = CollectorResult(bundle={})
    ce = session.client("ce", region_name="us-east-1")

    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=30)

    try:
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
        groups = []
        for r in resp.get("ResultsByTime", []):
            for g in r.get("Groups", []):
                amt = g["Metrics"]["UnblendedCost"]["Amount"]
                groups.append({"service": g["Keys"][0], "amount": float(amt)})
        out.bundle["cost_by_service_30d"] = groups
        out.bundle["cost_currency"] = resp.get("ResultsByTime", [{}])[0].get("Estimated", False)
    except ClientError as e:
        out.merge_errors("ce.get_cost_and_usage", e)
        out.bundle["cost_by_service_30d"] = []

    try:
        budgets = session.client("budgets")
        # Account ID required — caller passes via list_budgets with AccountId in API — actually DescribeBudgets needs AccountId
        sts = session.client("sts")
        aid = sts.get_caller_identity()["Account"]
        desc = budgets.describe_budgets(AccountId=aid)
        out.bundle["budgets"] = [
            {"name": b["BudgetName"], "limit": b.get("BudgetLimit", {}).get("Amount")}
            for b in desc.get("Budgets", [])[:50]
        ]
        out.bundle["budgets_configured"] = len(out.bundle["budgets"]) > 0
    except ClientError as e:
        out.bundle["budgets"] = []
        out.bundle["budgets_configured"] = False
        out.merge_errors("budgets.describe_budgets", e)

    # Trusted Advisor — Business / Enterprise support only
    try:
        sup = session.client("support", region_name="us-east-1")
        checks = sup.describe_trusted_advisor_checks(language="en")["checks"]
        cost_checks = [c for c in checks if c.get("category") == "cost_optimizing"]
        out.bundle["trusted_advisor_cost_check_ids"] = [c["id"] for c in cost_checks[:20]]
        summaries = []
        for cid in out.bundle["trusted_advisor_cost_check_ids"][:5]:
            try:
                fr = sup.describe_trusted_advisor_check_refresh_statuses(checkIds=[cid])["statuses"]
                summaries.append({"id": cid, "status": fr[0].get("status") if fr else None})
            except ClientError:
                summaries.append({"id": cid, "status": None})
        out.bundle["trusted_advisor_cost_sample"] = summaries
    except ClientError:
        out.bundle["trusted_advisor_cost_check_ids"] = []
        out.bundle["trusted_advisor_cost_sample"] = []

    return out


def merge_cost_bundle(result: CollectorResult) -> dict[str, Any]:
    base = dict(result.bundle)
    base["_collector_errors"] = result.errors
    return base
