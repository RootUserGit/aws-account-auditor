from unittest.mock import MagicMock, patch

from botocore.exceptions import NoCredentialsError

from audit_api.services.sts import verify_assume_role


def test_verify_assume_role_no_credentials_returns_tuple() -> None:
    with patch("audit_api.services.sts.boto3.client") as mock_client:
        mock_client.return_value.assume_role.side_effect = NoCredentialsError()
        ok, code, arn = verify_assume_role(
            "arn:aws:iam::123456789012:role/X",
            "external-id-12345678",
        )
    assert ok is False
    assert code == "NoCredentialsError"
    assert arn is None
