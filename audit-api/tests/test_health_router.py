from audit_api.routers.health import health


def test_health_payload() -> None:
    assert health() == {"status": "ok"}
