from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator


def _strip_env_tag(v: str) -> str:
    t = v.strip()
    if not t:
        raise ValueError("environment tag must not be empty")
    if len(t) > 128:
        raise ValueError("environment tag must be at most 128 characters")
    if any(ord(c) < 32 for c in t):
        raise ValueError("environment tag must not contain control characters")
    return t


class AwsAccountCreate(BaseModel):
    account_id: str = Field(..., min_length=12, max_length=12)
    role_arn: str
    external_id: str = Field(..., min_length=8, max_length=256)
    display_name: str = Field(..., min_length=1, max_length=255)
    environment: str = Field(..., min_length=1, max_length=128)

    @field_validator("account_id")
    @classmethod
    def digits(cls, v: str) -> str:
        if not re.fullmatch(r"\d{12}", v):
            raise ValueError("account_id must be 12 digits")
        return v

    @field_validator("display_name")
    @classmethod
    def strip_display_name(cls, v: str) -> str:
        t = v.strip()
        if not t:
            raise ValueError("display_name must not be empty")
        return t

    @field_validator("environment")
    @classmethod
    def strip_environment(cls, v: str) -> str:
        return _strip_env_tag(v)


class AwsAccountUpdate(BaseModel):
    display_name: str | None = Field(None, min_length=1, max_length=255)
    environment: str | None = Field(None, min_length=1, max_length=128)

    @field_validator("display_name")
    @classmethod
    def strip_display_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        t = v.strip()
        if not t:
            raise ValueError("display_name must not be empty")
        return t

    @field_validator("environment")
    @classmethod
    def strip_environment(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _strip_env_tag(v)

    @model_validator(mode="after")
    def at_least_one_field(self) -> AwsAccountUpdate:
        if self.display_name is None and self.environment is None:
            raise ValueError("At least one of display_name or environment must be provided")
        return self


class AwsAccountOut(BaseModel):
    id: UUID
    account_id: str
    display_name: str
    environment: str
    role_arn: str
    status: str
    last_verified_at: datetime | None
    last_verify_error_code: str | None = None

    model_config = {"from_attributes": True}


class AuditRunOut(BaseModel):
    id: UUID
    account_id: UUID
    created_at: datetime
    status: str
    rule_pack_version: str
    error_code: str | None
    summary_json: dict | None
    started_at: datetime | None
    finished_at: datetime | None
    #: Same human-readable context as list rows (failed/cancelled only)
    error_summary: str | None = None

    model_config = {"from_attributes": True}


class AuditRunListItem(BaseModel):
    """Lightweight row for scan history (no summary_json)."""

    id: UUID
    platform_account_id: UUID
    aws_account_id: str
    created_at: datetime
    status: str
    rule_pack_version: str
    error_code: str | None = None
    started_at: datetime | None
    finished_at: datetime | None
    #: Short human-readable failure context for terminal failed/cancelled rows
    error_summary: str | None = None


class FindingOut(BaseModel):
    id: UUID
    check_id: str
    pillar: str
    severity: str
    status: str
    war_theme: str | None
    cis_control: str | None = None
    resource_id: str | None
    # JSON column may be object or array (legacy rows); rules now normalize to dict
    evidence_json: dict[str, Any] | list[Any] | None = None
    remediation_hint: str | None

    model_config = {"from_attributes": True}
