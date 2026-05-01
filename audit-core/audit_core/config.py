import os


def database_url() -> str:
    return os.environ.get(
        "DATABASE_URL",
        "postgresql+psycopg://audit:audit@localhost:5432/audit",
    )
