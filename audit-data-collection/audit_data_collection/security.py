from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from audit_data_collection.cspm_signals import _policy_doc_has_star_action
from audit_data_collection.session import aws_session_client
from audit_data_collection.types import CollectorResult

# Sensitive TCP ports exposed to 0.0.0.0/0 (Trend EC2 / network hygiene).
_SENSITIVE_TCP_PORTS: tuple[tuple[int, str], ...] = (
    (22, "ssh"),
    (3389, "rdp"),
    (3306, "mysql"),
    (5432, "postgresql"),
    (1433, "mssql"),
    (1521, "oracle"),
    (27017, "mongodb"),
    (6379, "redis"),
    (9200, "opensearch"),
    (445, "smb"),
    (25, "smtp"),
    (23, "telnet"),
    (135, "rpc"),
    (11211, "memcached"),
    (80, "http"),
    (443, "https"),
)


def _tcp_covers_port(from_p: Any, to_p: Any, port: int) -> bool:
    try:
        if from_p is None or to_p is None:
            return False
        return int(from_p) <= port <= int(to_p)
    except (TypeError, ValueError):
        return False


def _iter_sensitive_ports_for_perm(proto: str, from_p: Any, to_p: Any) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    p = (proto or "").lower()
    if p == "-1":
        return [(port, label) for port, label in _SENSITIVE_TCP_PORTS]
    if p not in ("tcp", "6"):
        return out
    for port, label in _SENSITIVE_TCP_PORTS:
        if _tcp_covers_port(from_p, to_p, port):
            out.append((port, label))
    return out


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


def analyze_iam_credential_report(csv_text: str | None) -> dict[str, Any]:
    """Derive Trend/CSPM-style IAM signals from the credential report CSV."""
    empty = {
        "root_mfa_active": None,
        "users_with_password_and_active_key": [],
        "users_with_multiple_active_keys": [],
        "access_keys_older_than_days": [],
        "threshold_days": 90,
    }
    if not csv_text:
        return empty
    reader = csv.DictReader(io.StringIO(csv_text))
    stale: list[dict[str, Any]] = []
    pwd_and_key: list[str] = []
    multi: list[str] = []
    root_mfa: bool | None = None
    threshold = 90
    try:
        for row in reader:
            user = row.get("user") or ""
            if user == "<root_account>":
                root_mfa = row.get("mfa_active") == "true"
                continue
            pwd_on = row.get("password_enabled") == "true"
            k1 = row.get("access_key_1_active") == "true"
            k2 = row.get("access_key_2_active") == "true"
            if pwd_on and (k1 or k2):
                pwd_and_key.append(user)
            if k1 and k2:
                multi.append(user)
            for idx in (1, 2):
                if row.get(f"access_key_{idx}_active") != "true":
                    continue
                rot = row.get(f"access_key_{idx}_last_rotated") or ""
                if rot in ("N/A", "", "not_supported"):
                    continue
                age = _days_since_dt(rot)
                if age is not None and age > threshold:
                    stale.append({"user_name": user, "key_index": idx, "age_days": age})
    except Exception:
        return empty
    return {
        "root_mfa_active": root_mfa,
        "users_with_password_and_active_key": pwd_and_key,
        "users_with_multiple_active_keys": multi,
        "access_keys_older_than_days": stale,
        "threshold_days": threshold,
    }


def _cross_account_roles_missing_external_id(iam: Any, own_account: str, limit: int = 60) -> list[dict[str, Any]]:
    bad: list[dict[str, Any]] = []
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate(PaginationConfig={"PageSize": 25}):
            for role in page.get("Roles", []):
                if len(bad) >= limit:
                    return bad
                rn = role["RoleName"]
                try:
                    doc = iam.get_role(RoleName=rn)["Role"].get("AssumeRolePolicyDocument") or {}
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    stmts = doc.get("Statement", [])
                    if isinstance(stmts, dict):
                        stmts = [stmts]
                    for st in stmts:
                        if st.get("Effect") != "Allow":
                            continue
                        principal = st.get("Principal") or {}
                        if not isinstance(principal, dict):
                            continue
                        aws_val = principal.get("AWS")
                        if aws_val is None:
                            continue
                        principals = aws_val if isinstance(aws_val, list) else [aws_val]
                        for p in principals:
                            if not isinstance(p, str) or ":iam::" not in p:
                                continue
                            parts = p.split(":")
                            if len(parts) < 6:
                                continue
                            acct = parts[4]
                            if acct in ("", own_account):
                                continue
                            cond_raw = json.dumps(st.get("Condition") or {})
                            has_external_id = "sts:ExternalId" in cond_raw or '"ExternalId"' in cond_raw
                            if not has_external_id:
                                bad.append({"role_name": rn, "principal": p})
                                break
                except ClientError:
                    continue
            if len(bad) >= limit:
                break
    except ClientError:
        return bad
    return bad


def collect_security(session: boto3.Session, account_id: str) -> CollectorResult:
    """Gather security-relevant read-only signals (best-effort per API)."""
    out = CollectorResult(bundle={})

    # IAM account summary
    try:
        iam = aws_session_client(session,"iam")
        out.bundle["iam_summary"] = iam.get_account_summary()["SummaryMap"]
    except ClientError as e:
        out.merge_errors("iam.get_account_summary", e)

    try:
        iam = aws_session_client(session,"iam")
        out.bundle["iam_password_policy"] = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError:
        out.bundle["iam_password_policy"] = None

    # IAM credential report (optional)
    try:
        iam = aws_session_client(session,"iam")
        iam.generate_credential_report()
        report = iam.get_credential_report()["Content"].decode("utf-8")
        out.bundle["iam_credential_report_csv"] = report[:50000]  # cap size
    except ClientError:
        out.bundle["iam_credential_report_csv"] = None

    out.bundle["iam_credential_analysis"] = analyze_iam_credential_report(out.bundle.get("iam_credential_report_csv"))

    # Users without MFA (console users) — include metadata for reporting / UI
    try:
        iam = aws_session_client(session,"iam")
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

        # Users with AWS managed AdministratorAccess + compromised-key quarantine attachments
        admin_users: list[dict[str, Any]] = []
        compromised_users: list[dict[str, Any]] = []
        try:
            admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
            for row in users[:150]:
                uname = row["user_name"]
                try:
                    attached = iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", [])
                    for pol in attached:
                        par = pol.get("PolicyArn") or ""
                        pname = pol.get("PolicyName") or ""
                        if par == admin_arn:
                            admin_users.append({"user_name": uname, "policy_arn": admin_arn})
                        if "AWSCompromisedKeyQuarantine" in pname or "AWSCompromisedKeyQuarantine" in par:
                            compromised_users.append({"user_name": uname, "policy_arn": par})
                            break
                except ClientError:
                    continue
            out.bundle["iam_users_with_administrator_access"] = admin_users
            out.bundle["iam_users_compromised_key_quarantine"] = compromised_users
        except ClientError:
            out.bundle["iam_users_with_administrator_access"] = None
            out.bundle["iam_users_compromised_key_quarantine"] = None

        # Users missing group membership (subset)
        users_without_groups: list[str] = []
        try:
            for row in users[:120]:
                uname = row["user_name"]
                try:
                    groups = iam.list_groups_for_user(UserName=uname).get("Groups", [])
                    if not groups:
                        users_without_groups.append(uname)
                except ClientError:
                    continue
            out.bundle["iam_users_without_groups"] = users_without_groups
        except ClientError:
            out.bundle["iam_users_without_groups"] = None

        # Groups that still use inline policies
        groups_with_inline: list[dict[str, Any]] = []
        try:
            gp = iam.get_paginator("list_groups")
            for page in gp.paginate(PaginationConfig={"PageSize": 40}):
                for g in page.get("Groups", [])[:50]:
                    gn = g["GroupName"]
                    try:
                        inline = iam.list_group_policies(GroupName=gn).get("PolicyNames", [])
                        if inline:
                            groups_with_inline.append({"group_name": gn, "inline_policy_names": inline[:12]})
                    except ClientError:
                        continue
                    if len(groups_with_inline) >= 35:
                        break
                if len(groups_with_inline) >= 35:
                    break
            out.bundle["iam_groups_with_inline_policies"] = groups_with_inline
        except ClientError:
            out.bundle["iam_groups_with_inline_policies"] = None

        # Unused IAM groups (no members)
        unused_groups: list[str] = []
        try:
            gp = iam.get_paginator("list_groups")
            for page in gp.paginate(PaginationConfig={"PageSize": 40}):
                for g in page.get("Groups", [])[:80]:
                    gn = g["GroupName"]
                    try:
                        members = iam.get_group(GroupName=gn).get("Users", [])
                        if not members:
                            unused_groups.append(gn)
                    except ClientError:
                        continue
                if len(unused_groups) >= 40:
                    break
            out.bundle["iam_unused_groups"] = unused_groups[:40]
        except ClientError:
            out.bundle["iam_unused_groups"] = None

        # IAM roles trusted cross-account without ExternalId condition (sample)
        try:
            out.bundle["iam_cross_account_trust_without_external_id"] = _cross_account_roles_missing_external_id(
                iam, account_id, limit=50
            )
        except ClientError:
            out.bundle["iam_cross_account_trust_without_external_id"] = None

        # IAM user inline policies + wildcard sampling (Trend / AUD-001)
        iam_users_inline_policies: list[dict[str, Any]] = []
        iam_inline_policy_wildcard_hits: list[dict[str, Any]] = []
        iam_attached_policy_wildcard_hits: list[dict[str, Any]] = []
        try:
            for row in users[:28]:
                uname = row["user_name"]
                try:
                    inames = iam.list_user_policies(UserName=uname).get("PolicyNames", [])
                    if inames:
                        iam_users_inline_policies.append({"user_name": uname, "inline_policy_names": inames[:10]})
                    for pname in inames[:3]:
                        doc = iam.get_user_policy(UserName=uname, PolicyName=pname)["PolicyDocument"]
                        if isinstance(doc, str):
                            doc = json.loads(doc)
                        if _policy_doc_has_star_action(doc):
                            iam_inline_policy_wildcard_hits.append({"user_name": uname, "policy_name": pname})
                except ClientError:
                    continue
            for row in users[:12]:
                uname = row["user_name"]
                try:
                    attached = iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", [])
                    for pol in attached[:4]:
                        par = pol.get("PolicyArn") or ""
                        if "arn:aws:iam::aws:policy/" in par or ":policy/" not in par:
                            continue
                        try:
                            pol_meta = iam.get_policy(PolicyArn=par)["Policy"]
                            vers = pol_meta.get("DefaultVersionId")
                            if not vers:
                                continue
                            doc = iam.get_policy_version(PolicyArn=par, VersionId=vers)["PolicyVersion"]["Document"]
                            if isinstance(doc, str):
                                doc = json.loads(doc)
                            if _policy_doc_has_star_action(doc):
                                iam_attached_policy_wildcard_hits.append(
                                    {
                                        "user_name": uname,
                                        "policy_arn": par,
                                        "policy_name": pol.get("PolicyName"),
                                    }
                                )
                        except ClientError:
                            continue
                except ClientError:
                    continue
            out.bundle["iam_users_inline_policies"] = iam_users_inline_policies[:40]
            out.bundle["iam_inline_policy_wildcard_hits"] = iam_inline_policy_wildcard_hits[:30]
            out.bundle["iam_attached_policy_wildcard_hits"] = iam_attached_policy_wildcard_hits[:25]
        except Exception:
            out.bundle["iam_users_inline_policies"] = None
            out.bundle["iam_inline_policy_wildcard_hits"] = None
            out.bundle["iam_attached_policy_wildcard_hits"] = None
    except ClientError as e:
        out.merge_errors("iam.users_mfa", e)

    # IAM Access Analyzer — account analyzer in session home Region
    try:
        region = session.region_name or "us-east-1"
        aa = aws_session_client(session, "accessanalyzer", region_name=region)
        analyzers = aa.list_analyzers().get("analyzers", [])
        active = [a for a in analyzers if str(a.get("status", "")).upper() == "ACTIVE"]
        out.bundle["access_analyzer_active_count"] = len(active)
        out.bundle["access_analyzer_regions_checked"] = [region]
    except ClientError:
        out.bundle["access_analyzer_active_count"] = None

    # IAM server certificate expiry (metadata only)
    try:
        iam_certs = aws_session_client(session, "iam")
        cert_rows: list[dict[str, Any]] = []
        for meta in iam_certs.list_server_certificates().get("ServerCertificateMetadataList", [])[:35]:
            exp = meta.get("Expiration")
            row = {
                "name": meta.get("ServerCertificateName"),
                "expiration": exp.isoformat() if isinstance(exp, datetime) else str(exp),
                "days_to_expiry": None,
            }
            if isinstance(exp, datetime):
                exp_utc = exp if exp.tzinfo else exp.replace(tzinfo=timezone.utc)
                delta = exp_utc - datetime.now(timezone.utc)
                row["days_to_expiry"] = int(delta.total_seconds() / 86400)
            cert_rows.append(row)
        out.bundle["iam_server_certificates"] = cert_rows
    except ClientError:
        out.bundle["iam_server_certificates"] = None

    # S3 buckets + public access blocks
    try:
        s3 = aws_session_client(session,"s3")
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
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                row["default_encryption_enabled"] = len(rules) > 0
            except ClientError as ce:
                row["default_encryption_enabled"] = False
                row["encryption_error"] = ce.response.get("Error", {}).get("Code")
            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                row["versioning_status"] = ver.get("Status")
            except ClientError as ce:
                row["versioning_status"] = None
                row["versioning_error"] = ce.response.get("Error", {}).get("Code")
            try:
                s3.get_bucket_lifecycle_configuration(Bucket=name)
                row["lifecycle_configured"] = True
            except ClientError:
                row["lifecycle_configured"] = False
            try:
                logcfg = s3.get_bucket_logging(Bucket=name).get("LoggingEnabled") or {}
                row["server_access_logging_enabled"] = bool(logcfg.get("TargetBucket"))
            except ClientError as ce:
                row["server_access_logging_enabled"] = None
                row["logging_error"] = ce.response.get("Error", {}).get("Code")
            try:
                pst = s3.get_bucket_policy_status(Bucket=name)
                ps = pst.get("PolicyStatus") or {}
                row["bucket_policy_is_public"] = ps.get("IsPublic")
            except ClientError as ce:
                row["bucket_policy_is_public"] = None
                row["policy_status_error"] = ce.response.get("Error", {}).get("Code")
            try:
                pol_doc = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
                row["bucket_policy_present"] = True
                pol_txt = json.dumps(pol_doc).lower()
                row["bucket_policy_denies_insecure_transport"] = (
                    "securetransport" in pol_txt and "false" in pol_txt
                )
            except ClientError:
                row["bucket_policy_present"] = False
                row["bucket_policy_denies_insecure_transport"] = None
            bucket_pab.append(row)
        pub_names = [r.get("name") for r in bucket_pab if r.get("bucket_policy_is_public") is True][:45]
        out.bundle["s3_buckets"] = bucket_pab
        out.bundle["s3_bucket_public_acl_findings"] = pub_names
    except ClientError as e:
        out.merge_errors("s3.list_buckets", e)
        out.bundle["s3_bucket_public_acl_findings"] = None

    # Account-level public access block (S3 Control)
    try:
        s3ctl = aws_session_client(session,"s3control")
        r = s3ctl.get_public_access_block(AccountId=account_id)
        out.bundle["s3_account_public_access_block"] = r.get("PublicAccessBlockConfiguration")
    except ClientError as e:
        out.bundle["s3_account_public_access_block"] = None
        code = e.response.get("Error", {}).get("Code", "")
        if code not in ("NoSuchPublicAccessBlockConfiguration", "AccessDenied"):
            out.merge_errors("s3control.get_public_access_block", e)

    # EC2 default security groups (sample regions)
    try:
        ec2r = aws_session_client(session,"ec2", region_name=session.region_name or "us-east-1")
        regions = [r["RegionName"] for r in ec2r.describe_regions()["Regions"]][:12]
        default_sgs: list[dict[str, Any]] = []
        for region in regions:
            try:
                ec2 = aws_session_client(session,"ec2", region_name=region)
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

        # Security groups — sensitive TCP ports open to the Internet (0.0.0.0/0 or ::/0)
        world_open: list[dict[str, Any]] = []
        wide_open_ranges: list[dict[str, Any]] = []
        launch_wizard_sgs: list[dict[str, Any]] = []
        sg_high_rule_count: list[dict[str, Any]] = []
        sg_counts_by_region: list[dict[str, Any]] = []
        _max_world_findings = 160
        _wide_port_span = 900

        for region in regions:
            try:
                ec2 = aws_session_client(session, "ec2", region_name=region)
                region_sg_total = 0
                paginator = ec2.get_paginator("describe_security_groups")
                for page in paginator.paginate(PaginationConfig={"PageSize": 40}):
                    for sg in page.get("SecurityGroups", []):
                        region_sg_total += 1
                        gn = sg.get("GroupName") or ""
                        gid = sg.get("GroupId")
                        if gn.startswith("launch-wizard"):
                            launch_wizard_sgs.append(
                                {"region": region, "group_id": gid, "group_name": gn, "vpc_id": sg.get("VpcId")}
                            )
                        n_in = len(sg.get("IpPermissions", []))
                        n_out = len(sg.get("IpPermissionsEgress", []))
                        if n_in + n_out > 80:
                            sg_high_rule_count.append(
                                {
                                    "region": region,
                                    "group_id": gid,
                                    "group_name": gn,
                                    "ingress_rules": n_in,
                                    "egress_rules": n_out,
                                    "total_rules": n_in + n_out,
                                }
                            )

                        for perm in sg.get("IpPermissions", []):
                            proto = perm.get("IpProtocol", "")
                            from_p = perm.get("FromPort")
                            to_p = perm.get("ToPort")
                            try:
                                if (
                                    proto in ("tcp", "6")
                                    and from_p is not None
                                    and to_p is not None
                                    and int(to_p) - int(from_p) >= _wide_port_span
                                ):
                                    for rng in perm.get("IpRanges", []):
                                        if rng.get("CidrIp") in ("0.0.0.0/0", "::/0"):
                                            wide_open_ranges.append(
                                                {
                                                    "region": region,
                                                    "group_id": gid,
                                                    "group_name": gn,
                                                    "from_port": from_p,
                                                    "to_port": to_p,
                                                    "cidr": rng.get("CidrIp"),
                                                }
                                            )
                                    for rng in perm.get("Ipv6Ranges", []):
                                        if rng.get("CidrIpv6") == "::/0":
                                            wide_open_ranges.append(
                                                {
                                                    "region": region,
                                                    "group_id": gid,
                                                    "group_name": gn,
                                                    "from_port": from_p,
                                                    "to_port": to_p,
                                                    "cidr": "::/0",
                                                }
                                            )
                            except (TypeError, ValueError):
                                pass

                            sens = _iter_sensitive_ports_for_perm(proto, from_p, to_p)
                            if not sens:
                                continue
                            for rng in perm.get("IpRanges", []):
                                cidr = rng.get("CidrIp", "")
                                if cidr not in ("0.0.0.0/0", "::/0"):
                                    continue
                                for port, label in sens:
                                    if len(world_open) >= _max_world_findings:
                                        break
                                    world_open.append(
                                        {
                                            "region": region,
                                            "group_id": gid,
                                            "group_name": gn,
                                            "vpc_id": sg.get("VpcId"),
                                            "cidr": cidr,
                                            "from_port": from_p,
                                            "to_port": to_p,
                                            "matched_port": port,
                                            "matched_service": label,
                                        }
                                    )
                            for rng in perm.get("Ipv6Ranges", []):
                                if rng.get("CidrIpv6") != "::/0":
                                    continue
                                for port, label in sens:
                                    if len(world_open) >= _max_world_findings:
                                        break
                                    world_open.append(
                                        {
                                            "region": region,
                                            "group_id": gid,
                                            "group_name": gn,
                                            "vpc_id": sg.get("VpcId"),
                                            "cidr": "::/0",
                                            "from_port": from_p,
                                            "to_port": to_p,
                                            "matched_port": port,
                                            "matched_service": label,
                                        }
                                    )
                        if len(world_open) >= _max_world_findings:
                            break
                    if len(world_open) >= _max_world_findings:
                        break
                sg_counts_by_region.append({"region": region, "security_group_count": region_sg_total})
            except ClientError:
                continue

        out.bundle["ec2_world_open_ingress"] = world_open
        out.bundle["ec2_ssh_world_exposure"] = [r for r in world_open if r.get("matched_port") == 22][
            :80
        ]
        out.bundle["ec2_sg_wide_port_ranges_world"] = wide_open_ranges[:60]
        out.bundle["ec2_launch_wizard_security_groups"] = launch_wizard_sgs[:80]
        out.bundle["ec2_security_groups_high_rule_count"] = sg_high_rule_count[:60]
        out.bundle["ec2_security_group_counts_by_region"] = sg_counts_by_region

        # EC2 instances — inventory + posture sample (IAM, public IP, monitoring, SGs, …)
        imds_rows: list[dict[str, Any]] = []
        ec2_instance_posture: list[dict[str, Any]] = []
        ec2_inventory_total = 0
        _max_ec2_scan = 800
        _max_instance_detail = 160
        for region in regions:
            if ec2_inventory_total >= _max_ec2_scan:
                break
            try:
                ec2 = aws_session_client(session, "ec2", region_name=region)
                paginator = ec2.get_paginator("describe_instances")
                for page in paginator.paginate(PaginationConfig={"PageSize": 50}):
                    for rsv in page.get("Reservations", []):
                        for inst in rsv.get("Instances", []):
                            state = (inst.get("State") or {}).get("Name")
                            if state not in ("running", "stopped", "pending"):
                                continue
                            ec2_inventory_total += 1
                            iid = inst.get("InstanceId")
                            mo = inst.get("MetadataOptions") or {}
                            prof = inst.get("IamInstanceProfile") or {}
                            prof_arn = prof.get("Arn")
                            pub_ip = inst.get("PublicIpAddress")
                            pub_dns = inst.get("PublicDnsName")
                            enis = inst.get("NetworkInterfaces") or []
                            assoc_pub = any(bool(e.get("Association", {}).get("PublicIp")) for e in enis)
                            has_public = bool(pub_ip or assoc_pub)
                            mon = inst.get("Monitoring") or {}
                            sgs = [
                                {"group_id": x.get("GroupId"), "group_name": x.get("GroupName")}
                                for x in (inst.get("SecurityGroups") or [])
                            ]
                            lt = inst.get("LaunchTime")
                            lt_iso = lt.isoformat() if isinstance(lt, datetime) else str(lt) if lt else None
                            row_full: dict[str, Any] = {
                                "region": region,
                                "instance_id": iid,
                                "state": state,
                                "vpc_id": inst.get("VpcId"),
                                "subnet_id": inst.get("SubnetId"),
                                "image_id": inst.get("ImageId"),
                                "instance_type": inst.get("InstanceType"),
                                "launch_time": lt_iso,
                                "iam_instance_profile_arn": prof_arn,
                                "missing_iam_instance_profile": not (prof_arn or "").strip(),
                                "public_ipv4": pub_ip,
                                "public_dns_name": pub_dns,
                                "has_public_ip": has_public,
                                "monitoring_state": mon.get("State"),
                                "security_groups": sgs,
                                "uses_default_security_group": any(
                                    (x.get("group_name") or "") == "default" for x in sgs
                                ),
                                "network_interface_count": len(enis),
                                "key_name": inst.get("KeyName"),
                                "http_tokens": mo.get("HttpTokens"),
                                "http_endpoint": mo.get("HttpEndpoint"),
                                "subnet_associates_with_igw_route": None,
                                "disable_api_termination": None,
                                "scheduled_events": [],
                            }
                            if len(ec2_instance_posture) < _max_instance_detail:
                                ec2_instance_posture.append(row_full)
                            if len(imds_rows) < 120:
                                imds_rows.append(
                                    {
                                        "region": region,
                                        "instance_id": iid,
                                        "state": state,
                                        "http_tokens": mo.get("HttpTokens"),
                                        "http_endpoint": mo.get("HttpEndpoint"),
                                    }
                                )
                            if ec2_inventory_total >= _max_ec2_scan:
                                break
                    if ec2_inventory_total >= _max_ec2_scan:
                        break
            except ClientError:
                continue

        # Subnets — default route to Internet Gateway indicates a “public” subnet for sampled instances
        subnet_cache: dict[tuple[str, str], bool | None] = {}
        for row in ec2_instance_posture:
            sid = row.get("subnet_id")
            reg = row.get("region")
            if not sid or not reg:
                continue
            key = (reg, sid)
            if key in subnet_cache:
                row["subnet_associates_with_igw_route"] = subnet_cache[key]
                continue
            try:
                ec2 = aws_session_client(session, "ec2", region_name=reg)
                rts = ec2.describe_route_tables(
                    Filters=[{"Name": "association.subnet-id", "Values": [sid]}]
                ).get("RouteTables", [])
                igw_default = False
                for rt in rts:
                    for route in rt.get("Routes", []):
                        dest = route.get("DestinationCidrBlock") or ""
                        gw = route.get("GatewayId") or ""
                        if dest == "0.0.0.0/0" and gw.startswith("igw-"):
                            igw_default = True
                            break
                    if igw_default:
                        break
                subnet_cache[key] = igw_default if rts else None
            except ClientError:
                subnet_cache[key] = None
            row["subnet_associates_with_igw_route"] = subnet_cache[key]

        # Termination protection (sampled instances only — extra API calls)
        for row in ec2_instance_posture[:70]:
            iid = row.get("instance_id")
            reg = row.get("region")
            if not iid or not reg:
                continue
            try:
                ec2 = aws_session_client(session, "ec2", region_name=reg)
                attr = ec2.describe_instance_attribute(
                    InstanceId=iid, Attribute="disableApiTermination"
                )
                row["disable_api_termination"] = bool(
                    attr.get("DisableApiTermination", {}).get("Value")
                )
            except ClientError:
                row["disable_api_termination"] = None

        # Scheduled maintenance / events
        _sched_cap = 50
        sched_by_region: dict[str, list[str]] = {}
        for r in ec2_instance_posture[:_sched_cap]:
            rid = r.get("instance_id")
            rg = r.get("region")
            if rid and rg:
                sched_by_region.setdefault(rg, []).append(rid)
        ec2_scheduled_events: list[dict[str, Any]] = []
        for reg, ids in sched_by_region.items():
            chunk_size = 90
            try:
                ec2 = aws_session_client(session, "ec2", region_name=reg)
                for i in range(0, len(ids), chunk_size):
                    chunk = ids[i : i + chunk_size]
                    resp = ec2.describe_instance_status(
                        InstanceIds=chunk,
                        IncludeAllInstances=True,
                    )
                    for st in resp.get("InstanceStatuses", []):
                        evts = st.get("Events") or []
                        if not evts:
                            continue
                        ec2_scheduled_events.append(
                            {
                                "region": reg,
                                "instance_id": st.get("InstanceId"),
                                "events": [
                                    {
                                        "code": e.get("Code"),
                                        "description": (e.get("Description") or "")[:500],
                                        "not_before": str(e.get("NotBefore")) if e.get("NotBefore") else None,
                                    }
                                    for e in evts[:5]
                                ],
                            }
                        )
                    for row in ec2_instance_posture:
                        if row.get("region") != reg or row.get("instance_id") not in chunk:
                            continue
                        match = next(
                            (
                                st
                                for st in resp.get("InstanceStatuses", [])
                                if st.get("InstanceId") == row.get("instance_id")
                            ),
                            None,
                        )
                        if match and match.get("Events"):
                            row["scheduled_events"] = [
                                {"code": e.get("Code"), "description": (e.get("Description") or "")[:400]}
                                for e in (match.get("Events") or [])[:5]
                            ]
            except ClientError:
                continue

        out.bundle["ec2_instance_imds_posture"] = imds_rows
        out.bundle["ec2_instance_posture"] = ec2_instance_posture
        out.bundle["ec2_instance_inventory_count"] = ec2_inventory_total
        out.bundle["ec2_scheduled_instance_events"] = ec2_scheduled_events[:45]

        # Owned AMIs referenced by sampled instances — encryption + public launch permissions (per Region)
        ami_rows: list[dict[str, Any]] = []
        images_by_region: dict[str, set[str]] = {}
        for r in ec2_instance_posture:
            reg = r.get("region")
            img = r.get("image_id")
            if reg and img:
                images_by_region.setdefault(reg, set()).add(img)
        for region, id_set in images_by_region.items():
            ids_list = sorted(id_set)[:18]
            if not ids_list:
                continue
            try:
                ec2 = aws_session_client(session, "ec2", region_name=region)
                imgs = ec2.describe_images(Owners=["self"], ImageIds=ids_list).get("Images", [])
                for im in imgs:
                    iid_img = im.get("ImageId")
                    root_dev = im.get("RootDeviceName")
                    enc_ok = False
                    for bdm in im.get("BlockDeviceMappings") or []:
                        if bdm.get("DeviceName") != root_dev:
                            continue
                        ebs = bdm.get("Ebs") or {}
                        enc_ok = bool(ebs.get("Encrypted"))
                        break
                    public_launch = False
                    try:
                        if iid_img:
                            lp = ec2.describe_image_attribute(
                                ImageId=iid_img, Attribute="launchPermission"
                            ).get("LaunchPermissions", [])
                            public_launch = any(
                                p.get("Group") == "all" for p in lp if isinstance(p, dict)
                            )
                    except ClientError:
                        pass
                    ami_rows.append(
                        {
                            "region": region,
                            "image_id": iid_img,
                            "creation_date": im.get("CreationDate"),
                            "root_encrypted": enc_ok,
                            "public_launch_permission": public_launch,
                        }
                    )
            except ClientError:
                continue
        out.bundle["ec2_owned_ami_posture"] = ami_rows[:40]

        # Reserved Instances — expiring soon (cost)
        ri_expiring: list[dict[str, Any]] = []
        now = datetime.now(timezone.utc)
        for region in regions[:12]:
            try:
                ec2 = aws_session_client(session, "ec2", region_name=region)
                for ri in ec2.describe_reserved_instances().get("ReservedInstances", []):
                    if ri.get("State") != "active":
                        continue
                    end = ri.get("End")
                    if isinstance(end, datetime):
                        end_utc = end if end.tzinfo else end.replace(tzinfo=timezone.utc)
                        days_left = (end_utc - now).total_seconds() / 86400
                        if days_left <= 60:
                            ri_expiring.append(
                                {
                                    "region": region,
                                    "reserved_instances_id": ri.get("ReservedInstancesId"),
                                    "instance_type": ri.get("InstanceType"),
                                    "end": end_utc.isoformat(),
                                    "days_remaining": round(days_left, 1),
                                }
                            )
            except ClientError:
                continue
        out.bundle["ec2_reserved_instances_expiring"] = ri_expiring[:35]

        # Key pairs vs usage (cost / hygiene)
        unused_keypairs_by_region: list[dict[str, Any]] = []
        key_names_used = {
            (r.get("region"), r.get("key_name"))
            for r in ec2_instance_posture
            if r.get("key_name")
        }
        for region in regions[:12]:
            try:
                ec2 = aws_session_client(session, "ec2", region_name=region)
                pairs = ec2.describe_key_pairs().get("KeyPairs", [])
                names = [p.get("KeyName") for p in pairs if p.get("KeyName")]
                unused = [n for n in names if (region, n) not in key_names_used]
                if unused:
                    unused_keypairs_by_region.append(
                        {"region": region, "unused_key_pair_names": unused[:25], "unused_count": len(unused)}
                    )
            except ClientError:
                continue
        out.bundle["ec2_unused_key_pairs_by_region"] = unused_keypairs_by_region[:20]

        # Unattached ENIs (cost)
        unattached_enis: list[dict[str, Any]] = []
        for region in regions[:12]:
            try:
                ec2 = aws_session_client(session, "ec2", region_name=region)
                paginator = ec2.get_paginator("describe_network_interfaces")
                for page in paginator.paginate(
                    Filters=[{"Name": "status", "Values": ["available"]}],
                    PaginationConfig={"PageSize": 40, "MaxItems": 35},
                ):
                    for eni in page.get("NetworkInterfaces", []):
                        unattached_enis.append(
                            {
                                "region": region,
                                "network_interface_id": eni.get("NetworkInterfaceId"),
                                "description": (eni.get("Description") or "")[:120],
                            }
                        )
                        if len(unattached_enis) >= 45:
                            break
                    if len(unattached_enis) >= 45:
                        break
            except ClientError:
                continue
        out.bundle["ec2_unattached_network_interfaces"] = unattached_enis[:45]

        # Account EC2 instance limit signal (cost / capacity — sampled ratio)
        try:
            ec2_home = aws_session_client(session, "ec2", region_name=session.region_name or "us-east-1")
            attrs = ec2_home.describe_account_attributes(
                AttributeNames=["max-instances"]
            ).get("AccountAttributes", [])
            max_inst = None
            for a in attrs:
                if a.get("AttributeName") == "max-instances":
                    vals = a.get("AttributeValues") or []
                    if vals:
                        try:
                            max_inst = int(vals[0].get("AttributeValue", "0"))
                        except (TypeError, ValueError):
                            max_inst = None
                    break
            out.bundle["ec2_account_max_instances"] = max_inst
            out.bundle["ec2_instance_inventory_vs_limit_ratio"] = (
                float(ec2_inventory_total) / float(max_inst) if max_inst and max_inst > 0 else None
            )
        except ClientError:
            out.bundle["ec2_account_max_instances"] = None
            out.bundle["ec2_instance_inventory_vs_limit_ratio"] = None

        # Per-region EBS default encryption (sampled regions)
        ebs_enc_regions: list[dict[str, Any]] = []
        for region in regions:
            try:
                ec2 = aws_session_client(session,"ec2", region_name=region)
                r = ec2.get_ebs_encryption_by_default()
                ebs_enc_regions.append(
                    {"region": region, "ebs_encryption_by_default": bool(r.get("EbsEncryptionByDefault"))}
                )
            except ClientError as ce:
                ebs_enc_regions.append(
                    {
                        "region": region,
                        "ebs_encryption_by_default": None,
                        "error": ce.response.get("Error", {}).get("Code"),
                    }
                )
        out.bundle["ebs_default_encryption_by_region"] = ebs_enc_regions

        # RDS instances — public accessibility & storage encryption (sampled regions)
        rds_rows: list[dict[str, Any]] = []
        for region in regions:
            try:
                rds = aws_session_client(session,"rds", region_name=region)
                for db in rds.describe_db_instances().get("DBInstances", [])[:40]:
                    rds_rows.append(
                        {
                            "region": region,
                            "db_instance_identifier": db.get("DBInstanceIdentifier"),
                            "engine": db.get("Engine"),
                            "publicly_accessible": bool(db.get("PubliclyAccessible")),
                            "storage_encrypted": bool(db.get("StorageEncrypted")),
                            "backup_retention_period": int(db.get("BackupRetentionPeriod") or 0),
                            "auto_minor_version_upgrade": db.get("AutoMinorVersionUpgrade"),
                            "multi_az": db.get("MultiAZ"),
                            "deletion_protection": db.get("DeletionProtection"),
                        }
                    )
            except ClientError:
                continue
        out.bundle["rds_instances_posture"] = rds_rows[:120]

        # GuardDuty — detectors enabled in sampled regions
        gd_enabled_regions: list[str] = []
        for region in regions:
            try:
                gd = aws_session_client(session,"guardduty", region_name=region)
                ids = gd.list_detectors().get("DetectorIds", [])
                if not ids:
                    continue
                det = gd.get_detector(DetectorId=ids[0])
                if det.get("Status") == "ENABLED":
                    gd_enabled_regions.append(region)
            except ClientError:
                continue
        out.bundle["guardduty_summary"] = {
            "regions_sampled": regions,
            "enabled_regions": gd_enabled_regions,
            "enabled_regions_count": len(gd_enabled_regions),
        }

        # Customer-managed KMS keys — rotation status (sampled keys per region)
        kms_issues: list[dict[str, Any]] = []
        kms_checked = 0
        for region in regions:
            try:
                kms = aws_session_client(session,"kms", region_name=region)
                keys_collected: list[dict[str, Any]] = []
                try:
                    lp = kms.get_paginator("list_keys")
                    for page in lp.paginate(PaginationConfig={"PageSize": 15, "MaxItems": 40}):
                        keys_collected.extend(page.get("Keys", []))
                        if len(keys_collected) >= 40:
                            break
                except ClientError:
                    pass
                for entry in keys_collected[:25]:
                    kid = entry.get("KeyId")
                    if not kid:
                        continue
                    try:
                        meta = kms.describe_key(KeyId=kid)["KeyMetadata"]
                        if meta.get("KeyManager") != "CUSTOMER":
                            continue
                        key_state = meta.get("KeyState")
                        if key_state != "Enabled":
                            continue
                        kms_checked += 1
                        try:
                            rot = kms.get_key_rotation_status(KeyId=kid).get("KeyRotationEnabled")
                        except ClientError:
                            rot = None
                        if rot is False:
                            kms_issues.append(
                                {
                                    "region": region,
                                    "key_id": kid,
                                    "description": (meta.get("Description") or "")[:120],
                                }
                            )
                    except ClientError:
                        continue
            except ClientError:
                continue
        out.bundle["kms_customer_keys_rotation"] = {
            "customer_keys_checked": kms_checked,
            "keys_without_rotation": kms_issues[:40],
        }
    except ClientError as e:
        out.merge_errors("ec2.regions", e)

    # Lambda, ECS, Systems Manager, Secrets Manager (sampled regions)
    lambda_rows: list[dict[str, Any]] = []
    admin_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    try:
        ec2r2 = aws_session_client(session, "ec2", region_name=session.region_name or "us-east-1")
        lambda_regions = [r["RegionName"] for r in ec2r2.describe_regions()["Regions"]][:11]
    except ClientError:
        lambda_regions = [session.region_name or "us-east-1"]

    try:
        iam_client = aws_session_client(session, "iam")
        for region in lambda_regions:
            if len(lambda_rows) >= 48:
                break
            try:
                lam = aws_session_client(session, "lambda", region_name=region)
                for page in lam.get_paginator("list_functions").paginate(PaginationConfig={"PageSize": 20}):
                    for fn in page.get("Functions", []):
                        if len(lambda_rows) >= 48:
                            break
                        fname = fn["FunctionName"]
                        try:
                            cfg = lam.get_function_configuration(FunctionName=fname)
                        except ClientError:
                            continue
                        role_arn = (cfg.get("Role") or "").strip()
                        dlq = cfg.get("DeadLetterConfig") or {}
                        tracing_mode = (cfg.get("TracingConfig") or {}).get("Mode") or ""
                        kms_key = cfg.get("KMSKeyArn")
                        env_block = cfg.get("Environment") or {}
                        env_vars = env_block.get("Variables") or {}
                        pkg = cfg.get("PackageType") or "Zip"
                        code_signing = cfg.get("CodeSigningConfigArn")
                        reserved = cfg.get("ReservedConcurrentExecutions")

                        auth_type: str | None = None
                        has_url = False
                        try:
                            url_cfg = lam.get_function_url_config(FunctionName=fname)
                            has_url = True
                            auth_type = url_cfg.get("AuthType")
                        except ClientError as ue:
                            if ue.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                                pass

                        pc_units = 0
                        try:
                            for pc in lam.list_provisioned_concurrency_configs(FunctionName=fname).get(
                                "ProvisionedConcurrencyConfigs",
                                [],
                            ):
                                pc_units += int(pc.get("AllocatedProvisionedConcurrentExecutions") or 0)
                        except ClientError:
                            pass

                        inline_cnt = -1
                        admin_role = False
                        if role_arn and ":role/" in role_arn:
                            rn = role_arn.split(":role/", 1)[-1]
                            try:
                                inline_cnt = len(iam_client.list_role_policies(RoleName=rn).get("PolicyNames", []))
                                attached = iam_client.list_attached_role_policies(RoleName=rn).get(
                                    "AttachedPolicies",
                                    [],
                                )
                                admin_role = any(p.get("PolicyArn") == admin_policy_arn for p in attached)
                            except ClientError:
                                inline_cnt = -1

                        lambda_rows.append(
                            {
                                "region": region,
                                "function_name": fname,
                                "function_arn": cfg.get("FunctionArn"),
                                "runtime": cfg.get("Runtime"),
                                "package_type": pkg,
                                "role_arn": role_arn or None,
                                "dead_letter_target_arn": dlq.get("TargetArn"),
                                "tracing_mode": tracing_mode,
                                "kms_key_arn": kms_key,
                                "environment_variable_count": len(env_vars),
                                "has_function_url": has_url,
                                "function_url_auth_type": auth_type,
                                "code_signing_config_arn": code_signing,
                                "provisioned_concurrency_units": pc_units,
                                "reserved_concurrent_executions": reserved,
                                "execution_role_inline_policy_count": inline_cnt,
                                "execution_role_has_administrator_access": admin_role,
                            }
                        )
                    if len(lambda_rows) >= 48:
                        break
            except ClientError:
                continue
    except ClientError:
        pass
    out.bundle["lambda_functions_posture"] = lambda_rows

    ecs_rows: list[dict[str, Any]] = []
    try:
        for region in lambda_regions[:10]:
            try:
                ecs = aws_session_client(session, "ecs", region_name=region)
                clusters = ecs.list_clusters(maxResults=25).get("clusterArns", [])
                if not clusters:
                    continue
                desc = ecs.describe_clusters(clusters=clusters[:14], include=["SETTINGS"]).get("clusters", [])
                for c in desc:
                    insight_val = "disabled"
                    for s in c.get("settings", []) or []:
                        if s.get("name") == "containerInsights":
                            insight_val = (s.get("value") or "disabled").lower()
                            break
                    ecs_rows.append(
                        {
                            "region": region,
                            "cluster_arn": c.get("clusterArn"),
                            "cluster_name": c.get("clusterName"),
                            "container_insights": insight_val,
                        }
                    )
            except ClientError:
                continue
    except ClientError:
        pass
    out.bundle["ecs_clusters_posture"] = ecs_rows

    ssm_managed_total = 0
    ssm_regions_ok = 0
    try:
        for region in lambda_regions:
            try:
                ssm = aws_session_client(session, "ssm", region_name=region)
                paginator = ssm.get_paginator("describe_instance_information")
                for page in paginator.paginate(PaginationConfig={"PageSize": 50}):
                    ssm_managed_total += len(page.get("InstanceInformationList", []))
                ssm_regions_ok += 1
            except ClientError:
                continue
    except ClientError:
        pass
    out.bundle["ssm_managed_instance_count"] = ssm_managed_total if ssm_regions_ok > 0 else None

    secrets_rows: list[dict[str, Any]] = []
    try:
        for region in lambda_regions[:12]:
            try:
                sm = aws_session_client(session, "secretsmanager", region_name=region)
                lst = sm.list_secrets(MaxResults=50).get("SecretList", [])
                for s in lst[:30]:
                    arn = s.get("ARN")
                    if not arn:
                        continue
                    try:
                        d = sm.describe_secret(SecretId=arn)
                        secrets_rows.append(
                            {
                                "region": region,
                                "name": d.get("Name"),
                                "arn": arn,
                                "rotation_enabled": bool(d.get("RotationEnabled")),
                                "kms_key_id": (d.get("KmsKeyId") or ""),
                            }
                        )
                    except ClientError:
                        continue
                    if len(secrets_rows) >= 72:
                        break
            except ClientError:
                continue
            if len(secrets_rows) >= 72:
                break
    except ClientError:
        pass
    out.bundle["secrets_manager_posture"] = secrets_rows[:80]

    # AWS Config — optional
    try:
        cfg = aws_session_client(session,"config")
        status = cfg.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
        out.bundle["config_recorders"] = status
    except ClientError:
        out.bundle["config_recorders"] = None

    # Security Hub — optional
    try:
        sh = aws_session_client(session,"securityhub")
        out.bundle["security_hub_enabled"] = True
        findings = sh.get_findings(MaxResults=10, Filters={"WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}]})
        out.bundle["security_hub_sample_finding_count"] = len(findings.get("Findings", []))
    except ClientError:
        out.bundle["security_hub_enabled"] = False

    # CloudTrail trails (metadata + logging for sampled trails)
    try:
        ct = aws_session_client(session,"cloudtrail")
        trail_list = ct.describe_trails().get("trailList", [])[:18]
        rows: list[dict[str, Any]] = []
        for t in trail_list:
            rows.append(
                {
                    "name": t.get("Name"),
                    "trail_arn": t.get("TrailARN"),
                    "is_multi_region": t.get("IsMultiRegionTrail"),
                    "is_organization_trail": t.get("IsOrganizationTrail"),
                    "log_file_validation_enabled": t.get("LogFileValidationEnabled"),
                    "cloud_watch_logs_log_group_arn": t.get("CloudWatchLogsLogGroupArn"),
                    "is_logging": None,
                }
            )
        for i, t in enumerate(trail_list):
            try:
                status = ct.get_trail_status(Name=t["TrailARN"])
                if i < len(rows):
                    rows[i]["is_logging"] = status.get("IsLogging")
            except ClientError:
                pass
        out.bundle["cloudtrail_trails"] = rows
    except ClientError as e:
        out.bundle["cloudtrail_trails"] = []
        out.merge_errors("cloudtrail", e)

    # --- AUD-001: Trend-style supplemental inventory (sampled Regions, read-only) ---
    scan_regions: list[str] = []
    try:
        ec2r_scan = aws_session_client(session, "ec2", region_name=session.region_name or "us-east-1")
        scan_regions = [r["RegionName"] for r in ec2r_scan.describe_regions()["Regions"]][:12]
    except ClientError:
        scan_regions = [session.region_name or "us-east-1"]

    ebs_unenc: list[dict[str, Any]] = []
    gp2_in_use = 0
    total_flow = 0
    default_vpc_n = 0
    nat_total = 0
    alb_total = 0
    for reg in scan_regions:
        try:
            ec2 = aws_session_client(session, "ec2", region_name=reg)
            vols = ec2.describe_volumes(Filters=[{"Name": "status", "Values": ["in-use"]}], MaxResults=80).get(
                "Volumes", []
            )
            for vol in vols:
                if vol.get("Encrypted") is False and len(ebs_unenc) < 50:
                    ebs_unenc.append(
                        {
                            "region": reg,
                            "volume_id": vol.get("VolumeId"),
                            "size_gb": vol.get("Size"),
                            "volume_type": vol.get("VolumeType"),
                        }
                    )
                if (vol.get("VolumeType") or "").lower() == "gp2":
                    gp2_in_use += 1
            fl = ec2.describe_flow_logs(MaxResults=1000).get("FlowLogs", [])
            total_flow += len(fl)
            default_vpc_n += len(
                ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}]).get("Vpcs", [])
            )
            nat_total += len(ec2.describe_nat_gateways(MaxResults=500).get("NatGateways", []))
        except ClientError:
            continue
        try:
            elbv2 = aws_session_client(session, "elbv2", region_name=reg)
            alb_total += len(elbv2.describe_load_balancers().get("LoadBalancers", []))
        except ClientError:
            continue

    out.bundle["ebs_unencrypted_in_use_volumes"] = ebs_unenc[:50]
    out.bundle["vpc_flow_logs_account_summary"] = {"regions_sampled": scan_regions, "total_flow_logs": total_flow}
    out.bundle["ec2_default_vpc_count"] = default_vpc_n
    out.bundle["ec2_nat_gateway_total_count"] = nat_total
    out.bundle["ec2_alb_total_count"] = alb_total
    out.bundle["ebs_gp2_in_use_volume_count"] = gp2_in_use

    try:
        cw_home = aws_session_client(session, "cloudwatch", region_name=session.region_name or "us-east-1")
        out.bundle["cloudwatch_metric_alarm_count"] = len(
            cw_home.describe_alarms(MaxRecords=100).get("MetricAlarms", [])
        )
    except ClientError:
        out.bundle["cloudwatch_metric_alarm_count"] = None

    ddb_pitr: list[str] = []
    for reg in scan_regions[:8]:
        try:
            ddb = aws_session_client(session, "dynamodb", region_name=reg)
            names = ddb.list_tables(Limit=25).get("TableNames", [])
            for tbl in names:
                try:
                    pit = ddb.describe_continuous_backups(TableName=tbl).get("ContinuousBackupsDescription") or {}
                    st = (pit.get("PointInTimeRecoveryDescription") or {}).get("PointInTimeRecoveryStatus")
                    if st != "ENABLED":
                        ddb_pitr.append(f"{reg}:{tbl}")
                except ClientError:
                    continue
                if len(ddb_pitr) >= 40:
                    break
        except ClientError:
            continue
        if len(ddb_pitr) >= 40:
            break
    out.bundle["dynamodb_pitr_disabled_tables"] = ddb_pitr[:40]

    ec_unenc: list[dict[str, Any]] = []
    for reg in scan_regions[:8]:
        try:
            elc = aws_session_client(session, "elasticache", region_name=reg)
            for cls in elc.describe_cache_clusters(ShowCacheNodeInfo=False).get("CacheClusters", [])[:22]:
                if cls.get("AtRestEncryptionEnabled") is False:
                    ec_unenc.append({"region": reg, "cache_cluster_id": cls.get("CacheClusterId")})
        except ClientError:
            continue
    out.bundle["elasticache_unencrypted_clusters"] = ec_unenc[:30]

    efs_bad: list[dict[str, Any]] = []
    for reg in scan_regions[:8]:
        try:
            efs = aws_session_client(session, "efs", region_name=reg)
            for fs in efs.describe_file_systems(MaxItems=25).get("FileSystems", []):
                if fs.get("Encrypted") is False:
                    efs_bad.append({"region": reg, "file_system_id": fs.get("FileSystemId")})
        except ClientError:
            continue
    out.bundle["efs_unencrypted_file_systems"] = efs_bad[:25]

    ami_age: list[dict[str, Any]] = []
    for a in out.bundle.get("ec2_owned_ami_posture") or []:
        age = _days_since_dt(a.get("creation_date"))
        if age is not None and age > 180:
            row = dict(a)
            row["age_days"] = age
            ami_age.append(row)
    out.bundle["ec2_owned_ami_age_days_over_180"] = ami_age[:35]

    return out


def merge_security_bundle(result: CollectorResult) -> dict[str, Any]:
    """Flatten for rule engine consumption."""
    base = dict(result.bundle)
    base["_collector_errors"] = result.errors
    return base
