from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import sessionmaker

from audit_api.routers import accounts, health, runs
from audit_api.settings import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
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
