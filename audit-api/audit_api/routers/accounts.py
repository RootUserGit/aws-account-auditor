from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import delete
from sqlalchemy.orm import Session

from audit_api.deps import get_db, verify_api_key
from audit_api.schemas import AwsAccountCreate, AwsAccountOut
from audit_api.services.sts import verify_assume_role
from audit_core.models import Artifact, AuditRun, AwsAccount, AwsAccountStatus, Finding, Organization

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
) -> dict[str, str]:
    from redis import Redis
    from rq import Queue

    from audit_agents.worker import process_audit_run
    from audit_api.settings import settings
    from audit_core.models import AuditRun, AuditRunStatus

    org = _default_org(db)
    acc = db.query(AwsAccount).filter(AwsAccount.id == account_id, AwsAccount.org_id == org.id).first()
    if not acc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Account not found")
    run = AuditRun(account_id=acc.id, status=AuditRunStatus.queued.value, rule_pack_version="v1")
    db.add(run)
    db.commit()
    db.refresh(run)
    q = Queue(connection=Redis.from_url(settings.redis_url))
    q.enqueue(process_audit_run, str(run.id))
    return {"run_id": str(run.id), "status": run.status}
