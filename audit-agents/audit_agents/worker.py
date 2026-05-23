"""RQ worker entrypoint and audit job execution."""

from __future__ import annotations

import logging
import os
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from redis import Redis
from rq import SimpleWorker, Worker
from rq.timeouts import TimerDeathPenalty

from sqlalchemy import delete

from audit_agents.graph.audit_graph import run_audit_graph
from audit_agents.graph.state import AuditState
from audit_agents.json_sanitize import json_for_db
from audit_agents.rule_pack_path import sync_rule_pack_path_env
from audit_agents.run_progress import attach_run_progress_reporter, reset_run_progress_reporter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_DEFAULT_REDIS_URL = "redis://localhost:6379/0"


class WindowsSimpleWorker(SimpleWorker):
    """Local Windows dev only: in-process jobs (no ``fork``) + timer timeouts (no ``SIGALRM``).

    Production images run Linux and use the standard :class:`rq.Worker` with
    :class:`rq.timeouts.UnixSignalDeathPenalty`. This class is never selected there.
    """

    death_penalty_class = TimerDeathPenalty


def _worker_class() -> type[Worker]:
    """RQ's default worker forks per job and uses SIGALRM for timeouts — unavailable on Windows."""
    if sys.platform == "win32":
        return WindowsSimpleWorker
    return Worker


def _parse_dotenv_lines(raw: str) -> dict[str, str]:
    """Parse KEY=VALUE lines (comments and blank lines ignored). Shell never sees this."""
    out: dict[str, str] = {}
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("export "):
            s = s[7:].strip()
        if "=" not in s:
            continue
        key, _, val = s.partition("=")
        key = key.strip()
        if not key:
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        out[key] = val
    return out


def _dotenv_file_vars(path: Path) -> dict[str, str]:
    p = Path(path)
    if not p.is_file():
        return {}
    try:
        return _parse_dotenv_lines(p.read_text(encoding="utf-8"))
    except OSError:
        return {}


def load_worker_env(worker_file: Path | None = None) -> None:
    """Load layered `.env` files then defaults. Existing OS environment always wins.

    Files (later entries override earlier for duplicate keys), aligned with local API usage:
    ``<repo>/.env``, ``<repo>/audit-agents/.env``, ``<repo>/audit-agents/audit_agents/.env``,
    ``<repo>/audit-api/.env`` (same order idea as ``audit_api/settings.py``: API ``.env`` wins).

    Empty values from files are skipped so placeholders do not block boto3 from using explicit keys.

    After loading files, sets defaults matching ``audit_api/settings.py`` where unset:
    ``REDIS_URL``, ``RULE_PACK_PATH`` (repo ``rule_packs/v1``), ``ARTIFACTS_DIR`` (temp dir).
    """
    wf = Path(worker_file) if worker_file is not None else Path(__file__).resolve()
    repo_root = wf.parent.parent.parent
    audit_agents_pkg = wf.parent

    merged: dict[str, str] = {}
    for env_path in (
        repo_root / ".env",
        repo_root / "audit-agents" / ".env",
        audit_agents_pkg / ".env",
        repo_root / "audit-api" / ".env",
    ):
        merged.update(_dotenv_file_vars(env_path))

    for key, value in merged.items():
        if value == "":
            continue
        os.environ.setdefault(key, value)

    os.environ.setdefault("REDIS_URL", _DEFAULT_REDIS_URL)
    sync_rule_pack_path_env(Path(wf))
    os.environ.setdefault(
        "ARTIFACTS_DIR",
        str(Path(tempfile.gettempdir()) / "audit-artifacts"),
    )


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
        if run.status == AuditRunStatus.cancelled.value:
            logger.info("run %s already cancelled, skipping worker", run_id_str)
            return
        account = db.get(AwsAccount, run.account_id)
        if not account:
            run.status = AuditRunStatus.failed.value
            run.error_code = "AccountNotFound"
            run.finished_at = datetime.now(timezone.utc)
            db.commit()
            return

        now = datetime.now(timezone.utc)
        run.status = AuditRunStatus.running.value
        if run.started_at is None:
            run.started_at = now
        run.error_code = None
        run.summary_json = json_for_db({"progress": {"phase": "starting", "message": "Starting audit…"}})
        db.commit()

        initial: AuditState = {
            "run_id": run_id_str,
            "account_id": account.account_id,
            "role_arn": account.role_arn,
            "external_id": account.external_id,
        }

        def reporter(update: dict[str, Any]) -> None:
            try:
                db.refresh(run)
                cur = run.summary_json if isinstance(run.summary_json, dict) else {}
                prog = {**(cur.get("progress") or {}), **update}
                merged = {**cur, "progress": prog}
                run.summary_json = json_for_db(merged)
                db.commit()
            except Exception as e:
                logger.debug("run progress update skipped: %s", e)

        token = attach_run_progress_reporter(reporter)
        try:
            final = run_audit_graph(initial)
        finally:
            reset_run_progress_reporter(token)

        db.refresh(run)
        if run.status == AuditRunStatus.cancelled.value:
            if run.finished_at is None:
                run.finished_at = datetime.now(timezone.utc)
                db.commit()
            logger.info("audit run %s stopped (cancelled)", run_id_str)
            return

        db.execute(delete(Finding).where(Finding.run_id == run.id))
        db.execute(delete(Artifact).where(Artifact.run_id == run.id))

        err_code = final.get("error_code")
        err_msg = final.get("error")
        if err_code == "Cancelled" or (isinstance(err_msg, str) and "cancelled" in err_msg.lower()):
            run.status = AuditRunStatus.cancelled.value
            run.error_code = "Cancelled"
            run.summary_json = json_for_db({"cancelled": True, "detail": final.get("error")})
        elif final.get("error"):
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
                        cis_control=row.get("cis_control"),
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
    load_worker_env()
    redis_url = os.environ["REDIS_URL"]
    conn = Redis.from_url(redis_url)
    worker = _worker_class()(["default"], connection=conn)
    worker.work(with_scheduler=False)


if __name__ == "__main__":
    main()
