from audit_data_collection.normalize import merge_evidence


def test_merge_evidence_combines_errors() -> None:
    sec = {"iam_summary": {}, "_collector_errors": ["e1"]}
    cost = {"budgets": [], "_collector_errors": ["e2"]}
    m = merge_evidence(sec, cost)
    assert "iam_summary" in m
    assert m["_errors"] == ["e1", "e2"]
