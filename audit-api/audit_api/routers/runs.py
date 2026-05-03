from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import FileResponse
from redis import Redis
from rq.job import Job
from sqlalchemy.orm import Session

from audit_api.deps import get_db, verify_api_key
from audit_api.run_list import audit_run_to_list_item, audit_run_to_out
from audit_api.schemas import AuditRunListItem, AuditRunOut, FindingOut
from audit_api.settings import settings
from audit_core.models import Artifact, AuditRun, AuditRunStatus, AwsAccount, Finding, Organization

router = APIRouter(prefix="/runs", tags=["runs"])


def _default_org(db: Session) -> Organization:
    org = db.query(Organization).first()
    if not org:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="No organization seeded")
    return org


def _get_run_for_org(db: Session, run_id: UUID) -> AuditRun:
    org = _default_org(db)
    run = db.get(AuditRun, run_id)
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Run not found")
    acc = db.get(AwsAccount, run.account_id)
    if not acc or acc.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Run not found")
    return run


@router.get("", response_model=list[AuditRunListItem])
def list_runs(
    response: Response,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
    account_id: UUID | None = Query(
        None,
        description="Filter by aws_accounts.id (platform row UUID), not the 12-digit AWS account id",
    ),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
) -> list[AuditRunListItem]:
    """Audit runs for the default org: newest enqueue first (``created_at`` desc), then ``id``."""
    org = _default_org(db)
    base = (
        db.query(AuditRun, AwsAccount.account_id)
        .join(AwsAccount, AuditRun.account_id == AwsAccount.id)
        .filter(AwsAccount.org_id == org.id)
    )
    if account_id is not None:
        base = base.filter(AuditRun.account_id == account_id)
    total = base.count()
    response.headers["X-Total-Count"] = str(total)
    rows = (
        base.order_by(AuditRun.created_at.desc().nulls_last(), AuditRun.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [audit_run_to_list_item(run, str(aws_12)) for run, aws_12 in rows]


@router.post("/{run_id}/cancel", status_code=status.HTTP_200_OK)
def cancel_run(
    run_id: UUID,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> dict[str, bool]:
    """Mark run cancelled and attempt to dequeue the RQ job; worker exits cooperatively at gates."""
    run = _get_run_for_org(db, run_id)
    if run.status not in (AuditRunStatus.queued.value, AuditRunStatus.running.value):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={"message": "Run is not queued or running; nothing to cancel.", "status": run.status},
        )
    was_queued = run.status == AuditRunStatus.queued.value
    run.status = AuditRunStatus.cancelled.value
    run.error_code = "Cancelled"
    if was_queued:
        run.finished_at = datetime.now(timezone.utc)
    db.commit()
    if run.rq_job_id:
        try:
            conn = Redis.from_url(settings.redis_url)
            job = Job.fetch(run.rq_job_id, connection=conn)
            job.cancel()
        except Exception:
            pass
    return {"ok": True}


@router.get("/{run_id}", response_model=AuditRunOut)
def get_run(
    run_id: UUID,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> AuditRunOut:
    return audit_run_to_out(_get_run_for_org(db, run_id))


@router.get("/{run_id}/findings", response_model=list[FindingOut])
def list_findings(
    run_id: UUID,
    response: Response,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    pillar: str | None = None,
    severity: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
) -> list[Finding]:
    _get_run_for_org(db, run_id)
    q = db.query(Finding).filter(Finding.run_id == run_id)
    if pillar:
        q = q.filter(Finding.pillar == pillar)
    if severity:
        q = q.filter(Finding.severity == severity)
    if status_filter:
        q = q.filter(Finding.status == status_filter)
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    return q.offset(skip).limit(limit).all()


@router.get("/{run_id}/findings/{finding_id}", response_model=FindingOut)
def get_finding(
    run_id: UUID,
    finding_id: UUID,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> Finding:
    _get_run_for_org(db, run_id)
    f = db.query(Finding).filter(Finding.run_id == run_id, Finding.id == finding_id).first()
    if not f:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return f


@router.get("/{run_id}/report.html")
def download_report(
    run_id: UUID,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> FileResponse:
    _get_run_for_org(db, run_id)
    art = db.query(Artifact).filter(Artifact.run_id == run_id, Artifact.kind == "html").first()
    if not art:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Report not ready")
    path = Path(art.storage_uri)
    if not path.is_file():
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Report file missing")
    return FileResponse(path, media_type="text/html", filename="report.html")
