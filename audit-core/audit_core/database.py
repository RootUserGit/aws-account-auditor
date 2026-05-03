from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from audit_core.config import database_url

_engine = None
_SessionLocal = None


def get_engine():
    global _engine, _SessionLocal
    if _engine is None:
        _engine = create_engine(database_url(), pool_pre_ping=True)
        _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)
    return _engine


def session_scope() -> Generator[Session, None, None]:
    get_engine()
    db = _SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    from sqlalchemy import text

    from audit_core.models import Base

    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    # Lightweight additive migration for existing deployments (Postgres only).
    if engine.dialect.name == "postgresql":
        with engine.begin() as conn:
            conn.execute(
                text(
                    "ALTER TABLE aws_accounts ADD COLUMN IF NOT EXISTS "
                    "last_verify_error_code VARCHAR(128)"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE audit_runs ADD COLUMN IF NOT EXISTS "
                    "rq_job_id VARCHAR(128)"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE audit_runs ADD COLUMN IF NOT EXISTS "
                    "created_at TIMESTAMPTZ"
                )
            )
            conn.execute(
                text(
                    "UPDATE audit_runs SET created_at = COALESCE(started_at, finished_at, CURRENT_TIMESTAMP) "
                    "WHERE created_at IS NULL"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE audit_runs ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE audit_runs ALTER COLUMN created_at SET NOT NULL"
                )
            )
