# AWS Audit Platform (MVP)

Mono-repo aligned with the AWS Audit Agentic Platform plan: **Security + Cost** pillars, cross-account IAM role onboarding, async audits via Redis/RQ, LangGraph orchestration, and Next.js UI.

## Layout

| Directory | Role |
|-----------|------|
| `audit-contracts/` | OpenAPI + JSON Schema stubs |
| `audit-core/` | Shared SQLAlchemy models and DB helpers |
| `audit-api/` | FastAPI control plane |
| `audit-data-collection/` | boto3 collectors (security + cost) |
| `audit-agents/` | RQ worker + LangGraph audit graph + rule engine |
| `audit-llm/` | Stub LLM HTTP service |
| `audit-frontend/` | Next.js dashboard |
| `policies/` | Customer auditor IAM policy template |
| `rule_packs/v1/` | YAML rule definitions |

## Quick start

```bash
cp .env.example .env
# Set AUDIT_API_KEY and optionally AWS credentials for local tests
```

**Compose:** machines differ — use one of these:

```bash
docker compose up --build              # Compose V2 plugin (Docker Desktop, etc.)
docker-compose up --build              # Compose V1 standalone (hyphenated)
docker-compose -f docker-compose.yml build && docker-compose -f docker-compose.yml up
```

If you get `unknown flag: --build`, Docker does not have the `compose` plugin — use **`docker-compose`** or install [Compose V2](https://docs.docker.com/compose/install/). Put **`-f docker-compose.yml` before `up`**, not after.

Start your daemon first (Docker Desktop, or `colima start`).

**Verify semantics:** `POST .../verify` returns **HTTP 200** when the API processed the check. The JSON body `status` is **`verified`** if STS AssumeRole succeeded, or **`error`** if it failed (see **`last_verify_error_code`**, e.g. `AccessDenied`). Fix IAM trust / ExternalId / role ARN — not an HTTP failure.

**Platform AWS credentials:** `POST /accounts/{id}/verify` and the audit **worker** call `sts:AssumeRole` using the default boto3 credential chain. Put `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optionally `AWS_SESSION_TOKEN` in `.env` at the repo root, then run Compose with `docker-compose --env-file .env up` so **both** `audit-api` and `audit-worker` receive them. That principal must be trusted by each customer auditor role. Without credentials, verify returns **503** with a clear message instead of a 500.

- API: http://localhost:8000/docs  
- Frontend: http://localhost:3000  
- LLM stub: http://localhost:8001/health  

### Customer IAM role

See `policies/auditor-policy.json` and `policies/README.md`. Your platform role ARN and external ID are configured per AWS account record in the API.

### Remove an onboarded account (row)

- **UI:** Onboarding page → paste the row UUID → **Delete this row** (calls `DELETE /accounts/{uuid}`).
- **API:** `curl -X DELETE -H "X-API-Key: …" http://localhost:8000/accounts/<uuid>`
- **SQL (Postgres container):** use the **postgres** service user `audit`, not `root`:

```bash
docker compose exec postgres psql -U audit -d audit -c 'SELECT id, account_id, role_arn FROM aws_accounts;'
# then DELETE related rows or use the API delete above
```

## Development tests

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ./audit-core -e ./audit-data-collection -e ./audit-agents -e "./audit-api[dev]" pytest 'moto[s3,iam,sts]'
pytest audit-agents/tests audit-api/tests policies/tests audit-data-collection/tests -q
```

### Frontend e2e (Playwright)

```bash
cd audit-frontend && npx playwright install chromium && npm run test:e2e
```

The UI proxies API calls through `src/app/api/backend/[...path]` using server-side `AUDIT_API_URL` and `AUDIT_API_KEY` (set in Docker Compose).

## License

Proprietary / adjust as needed.
