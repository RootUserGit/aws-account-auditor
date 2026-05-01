from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def render_html_report(
    run_id: str,
    account_id: str,
    findings: list[dict[str, Any]],
    summary: dict[str, Any],
    llm_summary: dict[str, Any] | None,
) -> str:
    rows = []
    for f in findings:
        ev = f.get("evidence_json")
        ev_html = ""
        if ev is not None:
            try:
                ev_json = json.dumps(ev, indent=2, default=str)
            except TypeError:
                ev_json = str(ev)
            ev_html = (
                f"<details><summary>Evidence</summary>"
                f"<pre class='evidence'>{html.escape(ev_json)}</pre></details>"
            )
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(f.get('check_id','')))}</td>"
            f"<td>{html.escape(str(f.get('pillar','')))}</td>"
            f"<td>{html.escape(str(f.get('severity','')))}</td>"
            f"<td>{html.escape(str(f.get('status','')))}</td>"
            f"<td>{html.escape(str(f.get('remediation_hint') or ''))}</td>"
            f"<td>{ev_html}</td>"
            "</tr>"
        )
    llm_block = ""
    if llm_summary:
        llm_block = f"<pre>{html.escape(json.dumps(llm_summary, indent=2))}</pre>"
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><title>Audit {html.escape(run_id)}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 0.5rem; text-align: left; vertical-align: top; }}
th {{ background: #f4f4f4; }}
.summary {{ margin: 1rem 0; }}
pre.evidence {{ font-size: 11px; max-height: 24rem; overflow: auto; background: #fafafa; }}
details summary {{ cursor: pointer; font-weight: 600; }}
</style></head><body>
<h1>AWS Audit Report</h1>
<p>Run <code>{html.escape(run_id)}</code> · Account <code>{html.escape(account_id)}</code></p>
<div class="summary"><h2>Summary</h2><pre>{html.escape(json.dumps(summary, indent=2))}</pre></div>
<h2>Findings</h2>
<table><thead><tr><th>Check</th><th>Pillar</th><th>Severity</th><th>Status</th><th>Remediation</th><th>Details</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<h2>LLM summary (optional)</h2>
{llm_block}
</body></html>"""


def write_report(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
