from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import boto3
import httpx
from botocore.exceptions import ClientError
from langgraph.graph import END, START, StateGraph

from audit_data_collection.cost import collect_cost, merge_cost_bundle
from audit_data_collection.normalize import merge_evidence
from audit_data_collection.security import collect_security, merge_security_bundle
from audit_data_collection.session import session_from_credentials

from audit_agents.graph.state import AuditState
from audit_agents.reporting import render_html_report, write_report
from audit_agents.rules_engine import aggregate_counts, evaluate_all

logger = logging.getLogger(__name__)


def _rule_pack_dir() -> Path:
    return Path(os.environ.get("RULE_PACK_PATH", "/app/rule_packs/v1")).resolve()


def _artifacts_dir() -> Path:
    return Path(os.environ.get("ARTIFACTS_DIR", "/tmp/audit-artifacts")).resolve()


def node_assume_role(state: AuditState) -> dict[str, Any]:
    if state.get("error"):
        return {}
    try:
        sts = boto3.client("sts")
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
    session = session_from_credentials(state["credentials"])
    res = collect_security(session, state["account_id"])
    bundle = merge_security_bundle(res)
    return {"security_bundle": bundle}


def node_collect_cost(state: AuditState) -> dict[str, Any]:
    if state.get("error"):
        return {}
    session = session_from_credentials(state["credentials"])
    res = collect_cost(session)
    bundle = merge_cost_bundle(res)
    return {"cost_bundle": bundle}


def node_merge(state: AuditState) -> dict[str, Any]:
    if state.get("error"):
        return {}
    merged = merge_evidence(state.get("security_bundle") or {}, state.get("cost_bundle") or {})
    return {"merged_evidence": merged}


def node_evaluate(state: AuditState) -> dict[str, Any]:
    if state.get("error"):
        return {"findings": [], "summary": {}}
    findings = evaluate_all(state["merged_evidence"], _rule_pack_dir())
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
    g.add_node("collect_security", node_collect_security)
    g.add_node("collect_cost", node_collect_cost)
    g.add_node("merge", node_merge)
    g.add_node("evaluate", node_evaluate)
    g.add_node("summarize", node_optional_summarize)
    g.add_node("publish", node_publish_artifact)
    g.add_edge(START, "assume_role")
    g.add_edge("assume_role", "collect_security")
    g.add_edge("collect_security", "collect_cost")
    g.add_edge("collect_cost", "merge")
    g.add_edge("merge", "evaluate")
    g.add_edge("evaluate", "summarize")
    g.add_edge("summarize", "publish")
    g.add_edge("publish", END)
    return g.compile()


def run_audit_graph(initial: AuditState) -> AuditState:
    app = build_audit_graph()
    return app.invoke(initial)
