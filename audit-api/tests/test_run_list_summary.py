"""Tests for scan history row summaries."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from audit_api.run_list import audit_run_to_out, error_summary_for_list
from audit_core.models import AuditRun, AuditRunStatus


def _run(**kwargs) -> AuditRun:
    base = dict(
        id=uuid.uuid4(),
        account_id=uuid.uuid4(),
        created_at=datetime.now(timezone.utc),
        status=AuditRunStatus.failed.value,
        rule_pack_version="v1",
        error_code=None,
        summary_json=None,
        started_at=None,
        finished_at=None,
        rq_job_id=None,
    )
    base.update(kwargs)
    return AuditRun(**base)


def test_error_summary_failed_with_sts_message() -> None:
    r = _run(
        error_code="AccessDenied",
        summary_json={"error": "User foo is not authorized to perform: sts:AssumeRole on resource ..."},
    )
    s = error_summary_for_list(r)
    assert s is not None
    assert "AccessDenied" in s
    assert "AssumeRole" in s


def test_error_summary_non_terminal_returns_none() -> None:
    r = _run(status=AuditRunStatus.succeeded.value, summary_json={"error": "should ignore"})
    assert error_summary_for_list(r) is None


def test_error_summary_cancelled_uses_detail() -> None:
    r = _run(
        status=AuditRunStatus.cancelled.value,
        error_code="Cancelled",
        summary_json={"cancelled": True, "detail": "Stopped by user"},
    )
    s = error_summary_for_list(r)
    assert s is not None
    assert "Cancelled" in s


def test_audit_run_to_out_includes_error_summary() -> None:
    r = _run(
        error_code="AccessDenied",
        summary_json={"error": "Not authorized"},
    )
    out = audit_run_to_out(r)
    assert out.error_summary is not None
    assert "AccessDenied" in out.error_summary
