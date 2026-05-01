import json
from pathlib import Path


def test_auditor_policy_json_and_read_only_bias() -> None:
    path = Path(__file__).resolve().parents[1] / "auditor-policy.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["Version"] == "2012-10-17"
    actions = data["Statement"][0]["Action"]
    assert isinstance(actions, list)
    denied_writes = (
        "iam:CreateUser",
        "s3:DeleteBucket",
        "ec2:TerminateInstances",
    )
    for bad in denied_writes:
        assert bad not in actions
