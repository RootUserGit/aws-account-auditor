from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path
from typing import Any

import boto3
import httpx
from botocore.exceptions import ClientError
from langgraph.graph import END, START, StateGraph

from audit_data_collection.cost import collect_cost, merge_cost_bundle
from audit_data_collection.cspm_signals import build_cspm_signals
from audit_data_collection.normalize import merge_evidence
from audit_data_collection.security import collect_security, merge_security_bundle
from audit_data_collection.session import default_boto_config, session_from_credentials

from audit_agents.graph.state import AuditState
from audit_agents.reporting import render_html_report, write_report
from audit_agents.rule_pack_path import resolve_rule_pack_path
from audit_agents.rules_engine import aggregate_counts, evaluate_all
from audit_agents.run_progress import report_progress

logger = logging.getLogger(__name__)


def cancel_gate_check(state: AuditState) -> dict[str, Any]:
    """Cooperative cancel: UI/API sets audit_runs.status=cancelled; worker observes between heavy steps."""
    if state.get("error"):
        return {}
    if os.environ.get("AUDIT_SKIP_CANCEL_GATES") == "1":
        return {}
    try:
        from sqlalchemy.orm import sessionmaker

        from audit_core.database import get_engine
        from audit_core.models import AuditRun, AuditRunStatus

        Session = sessionmaker(bind=get_engine())
        db = Session()
        try:
            run = db.get(AuditRun, uuid.UUID(state["run_id"]))
            if run and run.status == AuditRunStatus.cancelled.value:
                return {
                    "error": "Audit cancelled by user.",
                    "error_code": "Cancelled",
                }
        finally:
            db.close()
    except Exception as e:
        logger.debug("cancel gate db check skipped: %s", e)
    return {}


def _rule_pack_dir() -> Path:
    return resolve_rule_pack_path(anchor=Path(__file__))


def _artifacts_dir() -> Path:
    return Path(os.environ.get("ARTIFACTS_DIR", "/tmp/audit-artifacts")).resolve()


def node_assume_role(state: AuditState) -> dict[str, Any]:
    if state.get("error"):
        return {}
    try:
        sts = boto3.client("sts", config=default_boto_config())
        resp = sts.assume_role(
            RoleArn=state["role_arn"],
            RoleSessionName=f"audit-{state['run_id'][:8]}",
            ExternalId=state["external_id"],
        )
        c = resp["Credentials"]
        creds = {
            "access_key_id": c["AccessKeyId"],
            "secret_access_key": c["SecretAccessKey"],
            "session_token": c["SessionToken"],
        }
        return {"credentials": creds, "error": None, "error_code": None}
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "AssumeRoleFailed")
        logger.warning("assume_role failed: %s", code)
        return {"error": str(e), "error_code": code, "credentials": {}}


def node_collect_security(state: AuditState) -> dict[str, Any]:
    if state.get("error"):
        return {}
    report_progress({"phase": "collect_security", "message": "Collecting security posture…"})
    session = session_from_credentials(state["credentials"])
    res = collect_security(session, state["account_id"])
    bundle = merge_security_bundle(res)
    return {"security_bundle": bundle}


def node_collect_cost(state: AuditState) -> dict[str, Any]:
    if state.get("error"):
        return {}
    report_progress({"phase": "collect_cost", "message": "Collecting cost & usage signals…"})
    session = session_from_credentials(state["credentials"])
    res = collect_cost(session)
    bundle = merge_cost_bundle(res)
    return {"cost_bundle": bundle}


def node_merge(state: AuditState) -> dict[str, Any]:
    if state.get("error"):
        return {}
    report_progress({"phase": "merge", "message": "Merging evidence…"})
    merged = merge_evidence(state.get("security_bundle") or {}, state.get("cost_bundle") or {})
    merged["cspm_signals"] = build_cspm_signals(merged, collector_errors=merged.get("_errors") or [])
    return {"merged_evidence": merged}


def node_evaluate(state: AuditState) -> dict[str, Any]:
    if state.get("error"):
        return {"findings": [], "summary": {}}
    pack_dir = _rule_pack_dir()

    def on_rule_progress(done: int, total: int) -> None:
        report_progress(
            {
                "phase": "evaluate",
                "rules_evaluated": done,
                "rules_total": total,
                "message": f"Evaluating rules ({done}/{total})…",
            }
        )

    findings = evaluate_all(state["merged_evidence"], pack_dir, on_rule_progress=on_rule_progress)
    summary = aggregate_counts(findings)
    return {"findings": findings, "summary": summary}


def node_optional_summarize(state: AuditState) -> dict[str, Any]:
    if state.get("error"):
        return {"llm_summary": None}
    url = os.environ.get("AUDIT_LLM_URL", "").rstrip("/")
    if not url:
        return {"llm_summary": None}
    try:
        payload = {
            "run_id": state["run_id"],
            "finding_count": len(state.get("findings") or []),
            "summary": state.get("summary") or {},
        }
        r = httpx.post(f"{url}/v1/summarize", json=payload, timeout=30.0)
        r.raise_for_status()
        return {"llm_summary": r.json()}
    except Exception as e:
        logger.info("llm summarize skipped or failed: %s", e)
        return {"llm_summary": None}


def node_publish_artifact(state: AuditState) -> dict[str, Any]:
    if state.get("error"):
        return {"artifact_path": None}
    path = _artifacts_dir() / str(state["run_id"]) / "report.html"
    body = render_html_report(
        state["run_id"],
        state["account_id"],
        state.get("findings") or [],
        state.get("summary") or {},
        state.get("llm_summary"),
    )
    write_report(path, body)
    return {"artifact_path": str(path)}


def build_audit_graph() -> Any:
    g = StateGraph(AuditState)
    g.add_node("assume_role", node_assume_role)
    g.add_node("gate_after_assume", cancel_gate_check)
    g.add_node("collect_security", node_collect_security)
    g.add_node("gate_after_security", cancel_gate_check)
    g.add_node("collect_cost", node_collect_cost)
    g.add_node("gate_after_cost", cancel_gate_check)
    g.add_node("merge", node_merge)
    g.add_node("evaluate", node_evaluate)
    g.add_node("gate_after_evaluate", cancel_gate_check)
    g.add_node("summarize", node_optional_summarize)
    g.add_node("publish", node_publish_artifact)
    g.add_edge(START, "assume_role")
    g.add_edge("assume_role", "gate_after_assume")
    g.add_edge("gate_after_assume", "collect_security")
    g.add_edge("collect_security", "gate_after_security")
    g.add_edge("gate_after_security", "collect_cost")
    g.add_edge("collect_cost", "gate_after_cost")
    g.add_edge("gate_after_cost", "merge")
    g.add_edge("merge", "evaluate")
    g.add_edge("evaluate", "gate_after_evaluate")
    g.add_edge("gate_after_evaluate", "summarize")
    g.add_edge("summarize", "publish")
    g.add_edge("publish", END)
    return g.compile()


def run_audit_graph(initial: AuditState) -> AuditState:
    app = build_audit_graph()
    return app.invoke(initial)
