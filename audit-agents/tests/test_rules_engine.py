import os
from pathlib import Path

import pytest

from audit_agents.rules_engine import EVALUATORS, aggregate_counts, evaluate_all, load_rule_definitions


@pytest.fixture
def pack_dir() -> Path:
    root = Path(__file__).resolve().parents[2]
    return root / "rule_packs" / "v1"


def test_iam_root_keys_pass(pack_dir: Path) -> None:
    ev = {"iam_summary": {"AccountAccessKeysPresent": 0}}
    rows = evaluate_all(ev, pack_dir)
    root_rule = next(r for r in rows if r["check_id"] == "SEC001_ROOT_ACCESS_KEYS")
    assert root_rule["status"] == "passed"


def test_cloudtrail_unknown_logging_status_uses_dict_evidence() -> None:
    trails = [{"Name": "t", "is_logging": None}]
    status, ev, _, _ = EVALUATORS["cloudtrail_logging_enabled"](
        {"cloudtrail_trails": trails}
    )
    assert status == "unknown"
    assert isinstance(ev, dict)
    assert ev["cloudtrail_trails"] == trails


def test_iam_mfa_failed_includes_user_metadata() -> None:
    from datetime import datetime, timezone

    created = datetime(2020, 1, 1, tzinfo=timezone.utc)
    users = [
        {
            "user_name": "alice",
            "create_date": created,
            "password_last_used": datetime(2024, 1, 1, tzinfo=timezone.utc),
        }
    ]
    status, ev, _, _ = EVALUATORS["iam_console_users_have_mfa"](
        {"iam_users_without_mfa": users}
    )
    assert status == "failed"
    assert isinstance(ev, dict)
    rows = ev["users_without_mfa"]
    assert isinstance(rows, list) and rows[0]["user_name"] == "alice"
    assert rows[0]["user_age_days"] is not None and rows[0]["user_age_days"] >= 1000


def test_config_recorder_failed_uses_dict_evidence() -> None:
    recs = [{"recording": False}]
    status, ev, _, _ = EVALUATORS["config_recorder_on"]({"config_recorders": recs})
    assert status == "failed"
    assert isinstance(ev, dict)
    assert ev["config_recorders"] == recs


def test_lambda_function_url_fails_without_iam() -> None:
    rows = [
        {
            "function_name": "fn",
            "has_function_url": True,
            "function_url_auth_type": "NONE",
        }
    ]
    status, ev, _, _ = EVALUATORS["lambda_function_url_requires_iam_auth"](
        {"lambda_functions_posture": rows}
    )
    assert status == "failed"
    assert len(ev.get("function_urls_without_iam_auth") or []) == 1


def test_rule_pack_loads_at_least_150(pack_dir: Path) -> None:
    rules = load_rule_definitions(pack_dir)
    assert len(rules) >= 150


def test_cspm_signal_evaluator_uses_merged_signals() -> None:
    ev = {"cspm_signals": {"IAM_CREDENTIAL_REPORT_MISSING": {"status": "passed", "evidence": {"ok": True}}}}
    status, ev_out, _, _ = EVALUATORS["cspm_signal"](ev, {"cspm_signal": "IAM_CREDENTIAL_REPORT_MISSING"})
    assert status == "passed"
    assert ev_out.get("ok") is True
    st2, _, _, _ = EVALUATORS["cspm_signal"](ev, {"cspm_signal": "NOT_A_REAL_SIGNAL_KEY"})
    assert st2 == "unknown"


def test_aggregate_counts(pack_dir: Path) -> None:
    ev = {"iam_summary": {"AccountAccessKeysPresent": 0}}
    rows = evaluate_all(ev, pack_dir)
    agg = aggregate_counts(rows)
    assert agg["total"] == len(rows)
    assert "by_status" in agg
    assert "groups" in agg and isinstance(agg["groups"], dict)
    assert "failed_groups" in agg


def test_graph_smoke_with_patched_collectors(
    pack_dir: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("RULE_PACK_PATH", str(pack_dir))
    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_SKIP_CANCEL_GATES", "1")
    monkeypatch.delenv("AUDIT_LLM_URL", raising=False)

    from audit_data_collection.types import CollectorResult

    def fake_assume(state):  # noqa: ANN001
        return {
            "credentials": {
                "access_key_id": "TESTKEY",
                "secret_access_key": "TESTSECRET",
                "session_token": "TOKEN",
            }
        }

    def fake_sec(session, account_id):  # noqa: ANN001
        return CollectorResult(
            bundle={
                "iam_summary": {"AccountAccessKeysPresent": 0},
                "iam_password_policy": {
                    "MinimumPasswordLength": 14,
                    "RequireSymbols": True,
                    "RequireNumbers": True,
                    "RequireUppercaseCharacters": True,
                    "RequireLowercaseCharacters": True,
                },
                "iam_credential_analysis": {
                    "root_mfa_active": True,
                    "users_with_password_and_active_key": [],
                    "users_with_multiple_active_keys": [],
                    "access_keys_older_than_days": [],
                    "threshold_days": 90,
                },
                "access_analyzer_active_count": 1,
                "iam_users_without_groups": [],
                "iam_groups_with_inline_policies": [],
                "iam_users_compromised_key_quarantine": [],
                "iam_cross_account_trust_without_external_id": [],
                "iam_server_certificates": [],
                "iam_unused_groups": [],
                "iam_users_without_mfa": [],
                "iam_users_with_administrator_access": [],
                "s3_buckets": [],
                "lambda_functions_posture": [],
                "ec2_instance_imds_posture": [],
                "ec2_instance_inventory_count": 0,
                "ecs_clusters_posture": [],
                "ssm_managed_instance_count": 0,
                "secrets_manager_posture": [],
                "s3_account_public_access_block": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                "ec2_default_security_groups": [],
                "ec2_world_open_ingress": [],
                "ec2_ssh_world_exposure": [],
                "ec2_sg_wide_port_ranges_world": [],
                "ec2_launch_wizard_security_groups": [],
                "ec2_security_groups_high_rule_count": [],
                "ec2_security_group_counts_by_region": [],
                "ec2_instance_posture": [],
                "ec2_scheduled_instance_events": [],
                "ec2_owned_ami_posture": [],
                "ec2_reserved_instances_expiring": [],
                "ec2_unused_key_pairs_by_region": [],
                "ec2_unattached_network_interfaces": [],
                "ec2_account_max_instances": None,
                "ec2_instance_inventory_vs_limit_ratio": None,
                "ebs_default_encryption_by_region": [
                    {"region": "us-east-1", "ebs_encryption_by_default": True},
                ],
                "rds_instances_posture": [],
                "guardduty_summary": {
                    "regions_sampled": ["us-east-1"],
                    "enabled_regions": ["us-east-1"],
                    "enabled_regions_count": 1,
                },
                "kms_customer_keys_rotation": {"customer_keys_checked": 0, "keys_without_rotation": []},
                "cloudtrail_trails": [
                    {
                        "name": "org-trail",
                        "is_logging": True,
                        "is_multi_region": True,
                        "log_file_validation_enabled": True,
                    }
                ],
                "config_recorders": [{"recording": True}],
                "security_hub_enabled": True,
                "iam_credential_report_csv": "user,access_key_1_active\nalice,false\n",
            }
        )

    def fake_cost(session):  # noqa: ANN001
        return CollectorResult(
            bundle={
                "cost_by_service_30d": [
                    {"service": "Amazon EC2", "amount": 5.0},
                    {"service": "Amazon S3", "amount": 3.0},
                ],
                "budgets_configured": True,
                "budgets": [{"name": "monthly", "limit": "500"}],
                "ec2_cost_signals": {
                    "regions_sampled": ["us-east-1"],
                    "unassociated_elastic_ips": [],
                    "unattached_ebs_volumes": [],
                    "stopped_ec2_instances": [],
                    "summary": {
                        "unassociated_elastic_ip_count": 0,
                        "unattached_volume_count": 0,
                        "stopped_instance_count": 0,
                        "unattached_volume_size_gb": 0,
                    },
                },
            }
        )

    monkeypatch.setattr("audit_agents.graph.audit_graph.node_assume_role", fake_assume)
    monkeypatch.setattr("audit_agents.graph.audit_graph.collect_security", fake_sec)
    monkeypatch.setattr("audit_agents.graph.audit_graph.collect_cost", fake_cost)

    from audit_agents.graph.audit_graph import run_audit_graph

    initial = {
        "run_id": "00000000-0000-0000-0000-000000000099",
        "account_id": "123456789012",
        "role_arn": "arn:aws:iam::123456789012:role/X",
        "external_id": "external-test-12345678",
    }
    out = run_audit_graph(initial)
    assert out.get("error") is None
    assert len(out.get("findings") or []) >= 70
    assert out.get("artifact_path")
