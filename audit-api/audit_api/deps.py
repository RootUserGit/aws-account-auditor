from __future__ import annotations

import os
import secrets
import uuid
from collections.abc import Generator

from fastapi import Depends, Header, HTTPException, status
from passlib.hash import bcrypt
from sqlalchemy.orm import Session

from audit_api.settings import settings


def _configure_db_env() -> None:
    os.environ.setdefault("DATABASE_URL", settings.database_url)


def get_db() -> Generator[Session, None, None]:
    _configure_db_env()
    from audit_core.database import get_engine
    from sqlalchemy.orm import sessionmaker

    SessionLocal = sessionmaker(bind=get_engine(), autoflush=False, autocommit=False)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_api_key(x_api_key: str | None = Header(None)) -> None:
    if not x_api_key or not secrets.compare_digest(x_api_key, settings.audit_api_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


def hash_api_key_for_storage(plain: str) -> str:
    return bcrypt.hash(plain)


def verify_org_api_key(db: Session, org_id: uuid.UUID, plain_key: str) -> bool:
    from audit_core.models import Organization

    org = db.get(Organization, org_id)
    if not org:
        return False
    return bcrypt.verify(plain_key, org.api_key_hash)
