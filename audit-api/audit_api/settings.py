from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://audit:audit@localhost:5432/audit"
    redis_url: str = "redis://localhost:6379/0"
    audit_api_key: str = "dev-change-me"
    cors_origins: str = "http://localhost:3000"


settings = Settings()
