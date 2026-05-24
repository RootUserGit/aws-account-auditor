"""Tests for CIS AWS Foundations Benchmark v1.5 aggregation helpers."""

from __future__ import annotations

from audit_agents.cis_controls_v15 import aggregate_cis_compliance, resolve_cis_control


def test_resolve_cis_control_yaml_override() -> None:
    rule = {"id": "SEC014_SG_SSH_OPEN_INTERNET", "cis_control": "9.9.9", "cspm_signal": "EC2_DEFAULT_VPC_PRESENT"}
    assert resolve_cis_control(rule) == "9.9.9"


def test_resolve_cis_control_from_check_id() -> None:
    rule = {"id": "SEC014_SG_SSH_OPEN_INTERNET", "evaluator": "noop"}
    assert resolve_cis_control(rule) == "5.2"


def test_resolve_cis_control_from_cspm_signal() -> None:
    rule = {"id": "SEC065_CSPM_TREND", "cspm_signal": "VPC_FLOW_LOGS_DISABLED"}
    assert resolve_cis_control(rule) == "3.1"


def test_aggregate_cis_compliance_score_and_band() -> None:
    findings = [
        {"status": "passed", "cis_control": "1.1"},
        {"status": "passed", "cis_control": "1.2"},
        {"status": "failed", "cis_control": "1.3"},
        {"status": "failed", "cis_control": "1.3"},
        {"status": "unknown", "cis_control": "1.4"},
    ]
    out = aggregate_cis_compliance(findings)
    assert out["mapped_checks_total"] == 5
    assert out["mapped_checks_passed"] == 2
    assert out["mapped_checks_failed"] == 2
    assert out["mapped_checks_unknown"] == 1
    assert out["score_percent"] == 40.0
    assert out["band"] == "red"
    assert out["failing_control_count"] == 1
    assert out["failing_control_ids"] == ["1.3"]


def test_aggregate_cis_band_at_eighty_percent_is_amber() -> None:
    """Spec: green strictly > 80%; 80% inclusive is amber."""
    findings = [{"status": "passed", "cis_control": "a"}, {"status": "failed", "cis_control": "b"}] * 5
    out = aggregate_cis_compliance(findings)
    assert out["score_percent"] == 50.0
    assert out["band"] == "amber"

    eight_pass_two_fail = [{"status": "passed", "cis_control": f"c{i}"} for i in range(8)]
    eight_pass_two_fail += [{"status": "failed", "cis_control": "x"}, {"status": "failed", "cis_control": "y"}]
    out80 = aggregate_cis_compliance(eight_pass_two_fail)
    assert out80["score_percent"] == 80.0
    assert out80["band"] == "amber"


def test_aggregate_cis_green_above_eighty() -> None:
    findings = [{"status": "passed", "cis_control": f"c{i}"} for i in range(9)]
    findings.append({"status": "failed", "cis_control": "z"})
    out = aggregate_cis_compliance(findings)
    assert out["score_percent"] == 90.0
    assert out["band"] == "green"


def test_aggregate_cis_empty_unmapped() -> None:
    assert aggregate_cis_compliance([])["score_percent"] is None
    assert aggregate_cis_compliance([{"status": "passed"}])["mapped_checks_total"] == 0
