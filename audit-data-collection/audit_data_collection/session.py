from __future__ import annotations

import os
from typing import Any

import boto3
from botocore.config import Config


def default_boto_config() -> Config:
    """Bounded socket timeouts so collectors fail fast instead of hanging until RQ kills the job."""
    connect = int(os.environ.get("AWS_CONNECT_TIMEOUT", "10"))
    read = int(os.environ.get("AWS_READ_TIMEOUT", "120"))
    return Config(
        connect_timeout=connect,
        read_timeout=read,
        retries={"max_attempts": 4, "mode": "standard"},
    )


def aws_session_client(session: boto3.Session, service_name: str, **kwargs: Any) -> Any:
    if "config" not in kwargs:
        kwargs["config"] = default_boto_config()
    return session.client(service_name, **kwargs)


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
