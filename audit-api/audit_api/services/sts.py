from __future__ import annotations

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def verify_assume_role(role_arn: str, external_id: str) -> tuple[bool, str | None, str | None]:
    """
    Attempt STS AssumeRole into customer role using platform credentials.
    Returns (ok, error_code, assumed_role_user_arn).
    """
    try:
        sts = boto3.client("sts")
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="audit-verify",
            ExternalId=external_id,
        )
        aid = resp.get("AssumedRoleUser", {}).get("Arn", "")
        return True, None, aid
    except NoCredentialsError:
        return False, "NoCredentialsError", None
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "AssumeRoleFailed")
        return False, code, None
