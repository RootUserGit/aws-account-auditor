from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from audit_data_collection.session import aws_session_client
from audit_data_collection.types import CollectorResult


def collect_cost(session: boto3.Session) -> CollectorResult:
    out = CollectorResult(bundle={})
    ce = aws_session_client(session, "ce", region_name="us-east-1")

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
        budgets = aws_session_client(session, "budgets")
        # Account ID required — caller passes via list_budgets with AccountId in API — actually DescribeBudgets needs AccountId
        sts = aws_session_client(session, "sts")
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
        sup = aws_session_client(session, "support", region_name="us-east-1")
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

    # EC2 waste signals — sampled regions (align with security collector footprint)
    try:
        ec2r = aws_session_client(session, "ec2", region_name=session.region_name or "us-east-1")
        regions = [r["RegionName"] for r in ec2r.describe_regions()["Regions"]][:8]
        unassociated_eips: list[dict[str, Any]] = []
        unattached_volumes: list[dict[str, Any]] = []
        stopped_instances: list[dict[str, Any]] = []
        for region in regions:
            try:
                ec2 = aws_session_client(session, "ec2", region_name=region)
                for addr in ec2.describe_addresses().get("Addresses", []):
                    if not addr.get("AssociationId"):
                        unassociated_eips.append(
                            {
                                "region": region,
                                "allocation_id": addr.get("AllocationId"),
                                "public_ip": addr.get("PublicIp"),
                            }
                        )
                vols = ec2.describe_volumes(
                    Filters=[{"Name": "status", "Values": ["available"]}]
                ).get("Volumes", [])
                for v in vols[:40]:
                    unattached_volumes.append(
                        {
                            "region": region,
                            "volume_id": v.get("VolumeId"),
                            "size_gb": v.get("Size"),
                            "volume_type": v.get("VolumeType"),
                            "snapshot_id": v.get("SnapshotId"),
                        }
                    )
                reservations = ec2.describe_instances(
                    Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
                ).get("Reservations", [])
                for res in reservations:
                    for inst in res.get("Instances", [])[:40]:
                        name_tag = None
                        for tag in inst.get("Tags") or []:
                            if tag.get("Key") == "Name":
                                name_tag = tag.get("Value")
                                break
                        lt = inst.get("LaunchTime")
                        launch_s = lt.isoformat() if hasattr(lt, "isoformat") else lt
                        placement = inst.get("Placement") or {}
                        stopped_instances.append(
                            {
                                "region": region,
                                "instance_id": inst.get("InstanceId"),
                                "instance_type": inst.get("InstanceType"),
                                "name_tag": name_tag,
                                "launch_time": launch_s,
                                "availability_zone": placement.get("AvailabilityZone"),
                                "vpc_id": inst.get("VpcId"),
                                "subnet_id": inst.get("SubnetId"),
                                "private_ip": inst.get("PrivateIpAddress"),
                                "state_transition_reason": (inst.get("StateTransitionReason") or "")[:240],
                            }
                        )
            except ClientError:
                continue
        out.bundle["ec2_cost_signals"] = {
            "regions_sampled": regions,
            "unassociated_elastic_ips": unassociated_eips[:50],
            "unattached_ebs_volumes": unattached_volumes[:80],
            "stopped_ec2_instances": stopped_instances[:80],
            "summary": {
                "unassociated_elastic_ip_count": len(unassociated_eips),
                "unattached_volume_count": len(unattached_volumes),
                "stopped_instance_count": len(stopped_instances),
                "unattached_volume_size_gb": sum(v.get("size_gb") or 0 for v in unattached_volumes),
            },
        }
    except ClientError as e:
        out.bundle["ec2_cost_signals"] = None
        out.merge_errors("ec2.cost_signals", e)

    return out


def merge_cost_bundle(result: CollectorResult) -> dict[str, Any]:
    base = dict(result.bundle)
    base["_collector_errors"] = result.errors
    return base
