from uuid import uuid4

from audit_api.schemas import FindingOut


def _finding(evidence):  # noqa: ANN001
    return FindingOut(
        id=uuid4(),
        check_id="x",
        pillar="SEC",
        severity="medium",
        status="unknown",
        war_theme=None,
        resource_id=None,
        evidence_json=evidence,
        remediation_hint=None,
    )


def test_finding_out_evidence_accepts_dict() -> None:
    f = _finding({"items": [1]})
    assert f.evidence_json == {"items": [1]}


def test_finding_out_evidence_accepts_list_legacy_rows() -> None:
    f = _finding([])
    assert f.evidence_json == []


def test_finding_out_evidence_accepts_none() -> None:
    f = _finding(None)
    assert f.evidence_json is None
