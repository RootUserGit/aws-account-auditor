"""precheck_failure_http_detail user-facing codes and messages."""

from audit_api.services.permission_precheck import PrecheckOutcome, precheck_failure_http_detail


def test_assume_role_denied_code() -> None:
    p = PrecheckOutcome(
        blocking=[
            {
                "id": "sts_assume_role",
                "label": "STS AssumeRole",
                "aws_error_code": "AccessDenied",
                "detail": "User is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::123:role/x",
                "iam_actions": ["sts:AssumeRole"],
            }
        ]
    )
    d = precheck_failure_http_detail(p)
    assert d["code"] == "ASSUME_ROLE_DENIED"
    assert "AssumeRole" in d["message"]
    assert "trust" in d["message"].lower() or "ExternalId" in d["message"]


def test_auditor_api_denied_code() -> None:
    p = PrecheckOutcome(
        blocking=[
            {
                "id": "iam_get_account_summary",
                "label": "IAM GetAccountSummary",
                "aws_error_code": "AccessDenied",
                "detail": "not authorized to perform: iam:GetAccountSummary",
                "iam_actions": ["iam:GetAccountSummary"],
            }
        ]
    )
    d = precheck_failure_http_detail(p)
    assert d["code"] == "AUDITOR_READ_API_DENIED"
    assert "read-only" in d["message"].lower() or "IAM" in d["message"]


def test_invalid_parameter_not_iam_message() -> None:
    p = PrecheckOutcome(
        blocking=[
            {
                "id": "rds_describe_db_instances",
                "label": "RDS DescribeDBInstances",
                "aws_error_code": "InvalidParameterValue",
                "detail": "Invalid value for MaxRecords",
                "iam_actions": ["rds:DescribeDBInstances"],
            }
        ]
    )
    d = precheck_failure_http_detail(p)
    assert d["code"] == "PRECHECK_INVALID_AWS_REQUEST"
    assert "platform bug" in d["message"].lower() or "parameter" in d["message"].lower()


def test_platform_credentials_code() -> None:
    p = PrecheckOutcome(
        blocking=[
            {
                "id": "platform_credentials_missing",
                "label": "Platform",
                "aws_error_code": "NoCredentialsError",
                "detail": "…",
            }
        ]
    )
    d = precheck_failure_http_detail(p)
    assert d["code"] == "PLATFORM_CREDENTIALS_MISSING"
