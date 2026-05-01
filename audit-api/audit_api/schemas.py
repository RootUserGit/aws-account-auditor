from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class AwsAccountCreate(BaseModel):
    account_id: str = Field(..., min_length=12, max_length=12)
    role_arn: str
    external_id: str = Field(..., min_length=8, max_length=256)

    @field_validator("account_id")
    @classmethod
    def digits(cls, v: str) -> str:
        if not re.fullmatch(r"\d{12}", v):
            raise ValueError("account_id must be 12 digits")
        return v


class AwsAccountOut(BaseModel):
    id: UUID
    account_id: str
    role_arn: str
    status: str
    last_verified_at: datetime | None
    last_verify_error_code: str | None = None

    model_config = {"from_attributes": True}


class AuditRunOut(BaseModel):
    id: UUID
    account_id: UUID
    status: str
    rule_pack_version: str
    error_code: str | None
    summary_json: dict | None
    started_at: datetime | None
    finished_at: datetime | None

    model_config = {"from_attributes": True}


class AuditRunListItem(BaseModel):
    """Lightweight row for scan history (no summary_json)."""

    id: UUID
    platform_account_id: UUID
    aws_account_id: str
    status: str
    rule_pack_version: str
    error_code: str | None = None
    started_at: datetime | None
    finished_at: datetime | None


class FindingOut(BaseModel):
    id: UUID
    check_id: str
    pillar: str
    severity: str
    status: str
    war_theme: str | None
    resource_id: str | None
    # JSON column may be object or array (legacy rows); rules now normalize to dict
    evidence_json: dict[str, Any] | list[Any] | None = None
    remediation_hint: str | None

    model_config = {"from_attributes": True}
