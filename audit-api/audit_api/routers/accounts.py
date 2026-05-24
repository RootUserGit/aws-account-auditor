from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import delete
from sqlalchemy.orm import Session

from audit_api.deps import get_db, verify_api_key
from audit_api.run_list import audit_run_to_list_item
from audit_api.schemas import AwsAccountCreate, AwsAccountOut, AwsAccountUpdate
from audit_api.services.permission_precheck import precheck_failure_http_detail, run_permission_precheck
from audit_api.services.sts import verify_assume_role
from audit_core.models import Artifact, AuditRun, AuditRunStatus, AwsAccount, AwsAccountStatus, Finding, Organization

router = APIRouter(prefix="/accounts", tags=["accounts"])


def _default_org(db: Session) -> Organization:
    org = db.query(Organization).first()
    if not org:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="No organization seeded")
    return org


@router.post("", response_model=AwsAccountOut)
def create_account(
    body: AwsAccountCreate,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> AwsAccount:
    org = _default_org(db)
    exists = db.query(AwsAccount).filter(AwsAccount.org_id == org.id, AwsAccount.account_id == body.account_id).first()
    if exists:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={
                "message": "This AWS account ID is already registered.",
                "existing_account_row_id": str(exists.id),
                "hint": "Use DELETE /accounts/{id} with existing_account_row_id, or verify/delete from the UI.",
            },
        )
    acc = AwsAccount(
        org_id=org.id,
        account_id=body.account_id,
        display_name=body.display_name,
        environment=body.environment,
        role_arn=body.role_arn,
        external_id=body.external_id,
        status=AwsAccountStatus.pending.value,
    )
    db.add(acc)
    db.commit()
    db.refresh(acc)
    return acc


@router.get("", response_model=list[AwsAccountOut])
def list_accounts(
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> list[AwsAccount]:
    org = _default_org(db)
    return db.query(AwsAccount).filter(AwsAccount.org_id == org.id).all()


@router.get("/meta/environment-tags", response_model=dict[str, list[str]])
def list_environment_tags(
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> dict[str, list[str]]:
    """Distinct environment tags for this org (one canonical spelling per case-insensitive key)."""
    org = _default_org(db)
    rows = (
        db.query(AwsAccount.environment)
        .filter(AwsAccount.org_id == org.id)
        .filter(AwsAccount.environment.isnot(None))
        .all()
    )
    by_lower: dict[str, str] = {}
    for (raw,) in rows:
        if not raw or not str(raw).strip():
            continue
        s = str(raw).strip()
        k = s.lower()
        if k not in by_lower:
            by_lower[k] = s
    tags = sorted(by_lower.values(), key=lambda x: x.lower())
    return {"tags": tags}


@router.get("/{account_id}", response_model=AwsAccountOut)
def get_account(
    account_id: UUID,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> AwsAccount:
    org = _default_org(db)
    acc = db.query(AwsAccount).filter(AwsAccount.id == account_id, AwsAccount.org_id == org.id).first()
    if not acc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Account not found")
    return acc


@router.post("/{account_id}/verify", response_model=AwsAccountOut)
def verify_account(
    account_id: UUID,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> AwsAccount:
    org = _default_org(db)
    acc = db.query(AwsAccount).filter(AwsAccount.id == account_id, AwsAccount.org_id == org.id).first()
    if not acc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Account not found")
    ok, code, _ = verify_assume_role(acc.role_arn, acc.external_id)
    if not ok and code == "NoCredentialsError":
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Platform AWS credentials are missing. Set AWS_ACCESS_KEY_ID and "
                "AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN if using temporary keys) "
                "for the audit-api container, or attach an IAM role that can sts:AssumeRole "
                "into the customer's auditor role. See README."
            ),
        )
    if ok:
        acc.status = AwsAccountStatus.verified.value
        acc.last_verified_at = datetime.now(timezone.utc)
        acc.last_verify_error_code = None
    else:
        acc.status = AwsAccountStatus.error.value
        acc.last_verify_error_code = code
    db.commit()
    db.refresh(acc)
    return acc


@router.patch("/{account_id}", response_model=AwsAccountOut)
def patch_account(
    account_id: UUID,
    body: AwsAccountUpdate,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> AwsAccount:
    org = _default_org(db)
    acc = db.query(AwsAccount).filter(AwsAccount.id == account_id, AwsAccount.org_id == org.id).first()
    if not acc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Account not found")
    if body.display_name is not None:
        acc.display_name = body.display_name
    if body.environment is not None:
        acc.environment = body.environment
    db.commit()
    db.refresh(acc)
    return acc


@router.delete("/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(
    account_id: UUID,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> Response:
    org = _default_org(db)
    acc = db.query(AwsAccount).filter(AwsAccount.id == account_id, AwsAccount.org_id == org.id).first()
    if not acc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Account not found")
    run_ids = [r.id for r in db.query(AuditRun.id).filter(AuditRun.account_id == acc.id).all()]
    if run_ids:
        db.execute(delete(Finding).where(Finding.run_id.in_(run_ids)))
        db.execute(delete(Artifact).where(Artifact.run_id.in_(run_ids)))
    db.execute(delete(AuditRun).where(AuditRun.account_id == acc.id))
    db.delete(acc)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{account_id}/runs", response_model=dict)
def enqueue_run(
    account_id: UUID,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> dict[str, Any]:
    from redis import Redis
    from rq import Queue

    from audit_agents.worker import process_audit_run
    from audit_api.settings import settings
    org = _default_org(db)
    acc = db.query(AwsAccount).filter(AwsAccount.id == account_id, AwsAccount.org_id == org.id).first()
    if not acc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Account not found")

    active = (
        db.query(AuditRun)
        .filter(
            AuditRun.account_id == acc.id,
            AuditRun.status.in_([AuditRunStatus.queued.value, AuditRunStatus.running.value]),
        )
        .first()
    )
    if active:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={
                "message": "An audit is already queued or running for this account. Wait for it to finish before starting another.",
                "active_run_id": str(active.id),
                "active_run_status": active.status,
            },
        )

    precheck = run_permission_precheck(acc.role_arn, acc.external_id)
    if precheck.blocking:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=precheck_failure_http_detail(precheck),
        )

    run = AuditRun(
        account_id=acc.id,
        status=AuditRunStatus.queued.value,
        rule_pack_version="v1",
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    q = Queue(connection=Redis.from_url(settings.redis_url))
    job = q.enqueue(process_audit_run, str(run.id), job_timeout=settings.audit_job_timeout_seconds)
    jid = getattr(job, "id", None)
    run.rq_job_id = str(jid) if jid is not None else None
    db.commit()
    out: dict[str, Any] = {
        "run_id": str(run.id),
        "status": run.status,
        "run": audit_run_to_list_item(run, acc.account_id).model_dump(mode="json"),
    }
    if precheck.warnings:
        out["precheck_warnings"] = precheck.warnings
    return out
