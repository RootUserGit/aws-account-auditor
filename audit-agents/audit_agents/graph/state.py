from __future__ import annotations

from typing import Any, Dict, List, Optional, TypedDict


class AuditState(TypedDict, total=False):
    run_id: str
    account_id: str
    role_arn: str
    external_id: str
    credentials: Dict[str, Any]
    security_bundle: Dict[str, Any]
    cost_bundle: Dict[str, Any]
    merged_evidence: Dict[str, Any]
    findings: List[Dict[str, Any]]
    summary: Dict[str, Any]
    llm_summary: Optional[Dict[str, Any]]
    artifact_path: Optional[str]
    error: Optional[str]
    error_code: Optional[str]
