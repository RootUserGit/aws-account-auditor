import os
from pathlib import Path

import pytest

from audit_agents.rules_engine import EVALUATORS, aggregate_counts, evaluate_all


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


def test_aggregate_counts(pack_dir: Path) -> None:
    ev = {"iam_summary": {"AccountAccessKeysPresent": 0}}
    rows = evaluate_all(ev, pack_dir)
    agg = aggregate_counts(rows)
    assert agg["total"] == len(rows)
    assert "by_status" in agg


def test_graph_smoke_with_patched_collectors(
    pack_dir: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("RULE_PACK_PATH", str(pack_dir))
    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path))
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
                "iam_password_policy": {"MinimumPasswordLength": 14},
                "iam_users_without_mfa": [],
                "s3_buckets": [],
                "s3_account_public_access_block": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                "ec2_default_security_groups": [],
                "cloudtrail_trails": [{"is_logging": True}],
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
    assert len(out.get("findings") or []) >= 10
    assert out.get("artifact_path")
