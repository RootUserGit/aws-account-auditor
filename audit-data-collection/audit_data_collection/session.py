from __future__ import annotations

from typing import Any

import boto3


def build_session(
    access_key_id: str,
    secret_access_key: str,
    session_token: str | None,
    region_name: str = "us-east-1",
) -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        aws_session_token=session_token,
        region_name=region_name,
    )


def session_from_credentials(creds: dict[str, Any], region_name: str = "us-east-1") -> boto3.Session:
    return build_session(
        creds["access_key_id"],
        creds["secret_access_key"],
        creds.get("session_token"),
        region_name=region_name,
    )
