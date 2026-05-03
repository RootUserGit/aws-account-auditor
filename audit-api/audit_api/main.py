from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import sessionmaker

from audit_api.routers import accounts, health, runs
from audit_api.settings import settings


def _apply_platform_aws_credentials_to_environ() -> None:
    """
    boto3 uses os.environ / shared credential files — it does not read Pydantic's .env by itself.
    After Settings loads AWS_* from layered .env files, mirror them into the process environment
    so STS AssumeRole and collectors use the intended platform principal.
    """
    if settings.aws_access_key_id:
        os.environ["AWS_ACCESS_KEY_ID"] = settings.aws_access_key_id
    if settings.aws_secret_access_key:
        os.environ["AWS_SECRET_ACCESS_KEY"] = settings.aws_secret_access_key
    if settings.aws_session_token:
        os.environ["AWS_SESSION_TOKEN"] = settings.aws_session_token
    if settings.aws_default_region:
        os.environ["AWS_DEFAULT_REGION"] = settings.aws_default_region


@asynccontextmanager
async def lifespan(app: FastAPI):
    _apply_platform_aws_credentials_to_environ()
    os.environ["DATABASE_URL"] = settings.database_url
    from audit_core.database import get_engine, init_db
    from audit_core.models import Organization

    init_db()
    Session = sessionmaker(bind=get_engine(), autoflush=False, autocommit=False)
    db = Session()
    try:
        if db.query(Organization).count() == 0:
            db.add(Organization(name="default", api_key_hash="-"))
            db.commit()
    finally:
        db.close()
    yield


app = FastAPI(title="AWS Audit API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(health.router)
app.include_router(accounts.router)
app.include_router(runs.router)
