from fastapi import FastAPI

app = FastAPI(title="Audit LLM Stub", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/summarize")
def summarize(body: dict) -> dict:
    """Return structured placeholder until real LLM wiring."""
    return {
        "summary": "Stub summary: review failed checks and cost concentration signals.",
        "top_actions": [
            "Remediate failed security checks first",
            "Validate AWS Budgets and Cost Explorer policies",
        ],
        "input_echo": {"run_id": body.get("run_id"), "finding_count": body.get("finding_count")},
    }
