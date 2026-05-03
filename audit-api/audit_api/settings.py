from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# audit_api/settings.py -> parent.parent is the audit-api package root (stable regardless of cwd).
_AUDIT_API_ROOT = Path(__file__).resolve().parent.parent
_REPO_ROOT = _AUDIT_API_ROOT.parent


def _layered_env_files() -> tuple[str, ...]:
    """Repo .env then audit-api/.env — later file wins. Paths are absolute so uvicorn cwd does not matter."""
    paths: list[Path] = []
    for p in (_REPO_ROOT / ".env", _AUDIT_API_ROOT / ".env"):
        if p.is_file():
            paths.append(p)
    return tuple(str(p) for p in paths)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_layered_env_files() or None,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "postgresql+psycopg://audit:audit@localhost:5432/audit"
    redis_url: str = "redis://localhost:6379/0"
    audit_api_key: str = "dev-change-me"
    cors_origins: str = "http://localhost:3000"
    #: RQ job timeout for one audit run (AWS collectors can be slow across regions).
    audit_job_timeout_seconds: int = 900

    #: Loaded from env / .env for Settings only — copied into os.environ at startup so boto3 uses them.
    aws_access_key_id: str | None = Field(default=None, validation_alias="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: str | None = Field(default=None, validation_alias="AWS_SECRET_ACCESS_KEY")
    aws_session_token: str | None = Field(default=None, validation_alias="AWS_SESSION_TOKEN")
    aws_default_region: str | None = Field(default=None, validation_alias="AWS_DEFAULT_REGION")


settings = Settings()
