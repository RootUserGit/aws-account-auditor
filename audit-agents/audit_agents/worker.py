"""RQ worker entrypoint and audit job execution."""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone

from redis import Redis
from rq import Worker

from sqlalchemy import delete

from audit_agents.graph.audit_graph import run_audit_graph
from audit_agents.graph.state import AuditState
from audit_agents.json_sanitize import json_for_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def process_audit_run(run_id_str: str) -> None:
    """Execute LangGraph audit pipeline and persist results."""
    # Deferred imports so `rq worker` can load module without DB at import time
    from sqlalchemy.orm import sessionmaker

    from audit_core.database import get_engine
    from audit_core.models import Artifact, AuditRun, AuditRunStatus, AwsAccount, Finding

    engine = get_engine()
    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        run = db.get(AuditRun, uuid.UUID(run_id_str))
        if not run:
            logger.error("run not found: %s", run_id_str)
            return
        account = db.get(AwsAccount, run.account_id)
        if not account:
            run.status = AuditRunStatus.failed.value
            run.error_code = "AccountNotFound"
            run.finished_at = datetime.now(timezone.utc)
            db.commit()
            return

        run.status = AuditRunStatus.running.value
        run.started_at = datetime.now(timezone.utc)
        run.error_code = None
        db.commit()

        initial: AuditState = {
            "run_id": run_id_str,
            "account_id": account.account_id,
            "role_arn": account.role_arn,
            "external_id": account.external_id,
        }
        final = run_audit_graph(initial)

        db.execute(delete(Finding).where(Finding.run_id == run.id))
        db.execute(delete(Artifact).where(Artifact.run_id == run.id))

        if final.get("error"):
            run.status = AuditRunStatus.failed.value
            run.error_code = final.get("error_code") or "AuditFailed"
            run.summary_json = json_for_db({"error": final.get("error")})
        else:
            run.status = AuditRunStatus.succeeded.value
            run.summary_json = json_for_db(final.get("summary") or {})
            for row in final.get("findings") or []:
                db.add(
                    Finding(
                        run_id=run.id,
                        check_id=row["check_id"],
                        pillar=row["pillar"],
                        severity=row["severity"],
                        status=row["status"],
                        war_theme=row.get("war_theme"),
                        resource_id=row.get("resource_id"),
                        evidence_json=json_for_db(row.get("evidence_json")),
                        remediation_hint=row.get("remediation_hint"),
                    )
                )
            ap = final.get("artifact_path")
            if ap:
                db.add(Artifact(run_id=run.id, kind="html", storage_uri=ap))

        run.finished_at = datetime.now(timezone.utc)
        db.commit()
        logger.info("audit run %s finished as %s", run_id_str, run.status)
    except Exception as e:
        logger.exception("audit run failed")
        try:
            db.rollback()
            run = db.get(AuditRun, uuid.UUID(run_id_str))
            if run:
                run.status = AuditRunStatus.failed.value
                run.error_code = type(e).__name__
                run.summary_json = {"error": str(e)}
                run.finished_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            db.rollback()
    finally:
        db.close()


def main() -> None:
    redis_url = os.environ["REDIS_URL"]
    conn = Redis.from_url(redis_url)
    worker = Worker(["default"], connection=conn)
    worker.work(with_scheduler=False)


if __name__ == "__main__":
    main()
