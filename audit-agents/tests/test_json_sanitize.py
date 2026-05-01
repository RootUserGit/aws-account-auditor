from datetime import date, datetime, timezone

from audit_agents.json_sanitize import json_for_db


def test_json_for_db_datetime_nested() -> None:
    dt = datetime(2024, 6, 1, 12, 0, tzinfo=timezone.utc)
    out = json_for_db({"trail": {"Created": dt}, "items": [1, dt]})
    assert out["trail"]["Created"] == "2024-06-01T12:00:00+00:00"
    assert out["items"][1] == "2024-06-01T12:00:00+00:00"


def test_json_for_db_date() -> None:
    assert json_for_db(date(2024, 1, 2)) == "2024-01-02"


def test_json_for_db_passthrough() -> None:
    assert json_for_db({"a": 1, "b": None}) == {"a": 1, "b": None}
