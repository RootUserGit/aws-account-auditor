"""Tests for AWS account request/response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from audit_api.schemas import AwsAccountCreate, AwsAccountOut, AwsAccountUpdate
from audit_core.models import AwsAccount, AwsAccountStatus


def test_aws_account_create_strips_display_name() -> None:
    m = AwsAccountCreate(
        account_id="123456789012",
        role_arn="arn:aws:iam::123456789012:role/auditor",
        external_id="12345678ab",
        display_name="  Prod workload  ",
        environment="production",
    )
    assert m.display_name == "Prod workload"
    assert m.environment == "production"


def test_aws_account_create_prod_distinct_from_production() -> None:
    a = AwsAccountCreate(
        account_id="123456789012",
        role_arn="arn:aws:iam::123456789012:role/auditor",
        external_id="12345678ab",
        display_name="x",
        environment="PROD",
    )
    b = AwsAccountCreate(
        account_id="123456789013",
        role_arn="arn:aws:iam::123456789013:role/auditor",
        external_id="12345678ab",
        display_name="y",
        environment="production",
    )
    assert a.environment == "PROD"
    assert b.environment == "production"


def test_aws_account_create_rejects_bad_account_id() -> None:
    with pytest.raises(ValidationError):
        AwsAccountCreate(
            account_id="123",
            role_arn="arn:aws:iam::123456789012:role/auditor",
            external_id="12345678ab",
            display_name="x",
            environment="other",
        )


def test_aws_account_create_rejects_empty_display_name() -> None:
    with pytest.raises(ValidationError):
        AwsAccountCreate(
            account_id="123456789012",
            role_arn="arn:aws:iam::123456789012:role/auditor",
            external_id="12345678ab",
            display_name="   ",
            environment="staging",
        )


def test_aws_account_update_requires_at_least_one_field() -> None:
    with pytest.raises(ValidationError):
        AwsAccountUpdate()


def test_aws_account_update_display_name_only() -> None:
    u = AwsAccountUpdate(display_name="Renamed")
    assert u.environment is None
    assert u.display_name == "Renamed"


def test_aws_account_out_from_orm() -> None:
    oid = uuid.uuid4()
    aid = uuid.uuid4()
    now = datetime.now(timezone.utc)
    acc = AwsAccount(
        id=aid,
        org_id=oid,
        account_id="999888777666",
        display_name="Sandbox",
        environment="pre-prod",
        role_arn="arn:aws:iam::999888777666:role/r",
        external_id="extid12345678",
        status=AwsAccountStatus.verified.value,
        last_verified_at=now,
        last_verify_error_code=None,
    )
    out = AwsAccountOut.model_validate(acc)
    assert out.display_name == "Sandbox"
    assert out.environment == "pre-prod"
    assert out.account_id == "999888777666"
