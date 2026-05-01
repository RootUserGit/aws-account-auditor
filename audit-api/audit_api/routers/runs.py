from __future__ import annotations

from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from audit_api.deps import get_db, verify_api_key
from audit_api.schemas import AuditRunListItem, AuditRunOut, FindingOut
from audit_core.models import Artifact, AuditRun, AwsAccount, Finding, Organization

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
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
    account_id: UUID | None = Query(
        None,
        description="Filter by aws_accounts.id (platform row UUID), not the 12-digit AWS account id",
    ),
    limit: int = Query(50, ge=1, le=200),
) -> list[AuditRunListItem]:
    """Recent audit runs for the default org (newest first)."""
    org = _default_org(db)
    q = (
        db.query(AuditRun, AwsAccount.account_id)
        .join(AwsAccount, AuditRun.account_id == AwsAccount.id)
        .filter(AwsAccount.org_id == org.id)
    )
    if account_id is not None:
        q = q.filter(AuditRun.account_id == account_id)
    rows = q.order_by(AuditRun.id.desc()).limit(limit).all()
    return [
        AuditRunListItem(
            id=run.id,
            platform_account_id=run.account_id,
            aws_account_id=str(aws_12),
            status=run.status,
            rule_pack_version=run.rule_pack_version,
            error_code=run.error_code,
            started_at=run.started_at,
            finished_at=run.finished_at,
        )
        for run, aws_12 in rows
    ]


@router.get("/{run_id}", response_model=AuditRunOut)
def get_run(
    run_id: UUID,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> AuditRun:
    return _get_run_for_org(db, run_id)


@router.get("/{run_id}/findings", response_model=list[FindingOut])
def list_findings(
    run_id: UUID,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    pillar: str | None = None,
    severity: str | None = None,
) -> list[Finding]:
    _get_run_for_org(db, run_id)
    q = db.query(Finding).filter(Finding.run_id == run_id)
    if pillar:
        q = q.filter(Finding.pillar == pillar)
    if severity:
        q = q.filter(Finding.severity == severity)
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
