"""Shared helpers for audit run list rows (history table + enqueue response)."""

from __future__ import annotations

from audit_api.schemas import AuditRunListItem, AuditRunOut
from audit_core.models import AuditRun, AuditRunStatus

_SUMMARY_MAX_LEN = 480


def error_summary_for_list(run: AuditRun) -> str | None:
    """One-line explanation for failed/cancelled rows (history + tooltips)."""
    if run.status not in (
        AuditRunStatus.failed.value,
        AuditRunStatus.cancelled.value,
    ):
        return None
    chunks: list[str] = []
    if run.error_code and str(run.error_code).strip():
        chunks.append(str(run.error_code).strip())
    sj = run.summary_json
    if isinstance(sj, dict):
        err = sj.get("error")
        if isinstance(err, str) and err.strip():
            chunks.append(err.strip())
        elif run.status == AuditRunStatus.cancelled.value:
            det = sj.get("detail")
            if isinstance(det, str) and det.strip():
                chunks.append(det.strip())
    if not chunks:
        return run.error_code
    # Prefer code + message when both exist (e.g. AccessDenied + STS message)
    if len(chunks) >= 2:
        msg = f"{chunks[0]}: {chunks[1]}"
    else:
        msg = chunks[0]
    if len(msg) > _SUMMARY_MAX_LEN:
        return msg[: _SUMMARY_MAX_LEN - 1] + "…"
    return msg


def audit_run_to_out(run: AuditRun) -> AuditRunOut:
    """Full run payload for GET /runs/{id} (includes computed ``error_summary``)."""
    return AuditRunOut(
        id=run.id,
        account_id=run.account_id,
        created_at=run.created_at,
        status=run.status,
        rule_pack_version=run.rule_pack_version,
        error_code=run.error_code,
        summary_json=run.summary_json,
        started_at=run.started_at,
        finished_at=run.finished_at,
        error_summary=error_summary_for_list(run),
    )


def audit_run_to_list_item(run: AuditRun, aws_account_id_12: str) -> AuditRunListItem:
    return AuditRunListItem(
        id=run.id,
        platform_account_id=run.account_id,
        aws_account_id=aws_account_id_12,
        created_at=run.created_at,
        status=run.status,
        rule_pack_version=run.rule_pack_version,
        error_code=run.error_code,
        started_at=run.started_at,
        finished_at=run.finished_at,
        error_summary=error_summary_for_list(run),
    )
