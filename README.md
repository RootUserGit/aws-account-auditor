# AWS Audit Platform (MVP)

Mono-repo aligned with the AWS Audit Agentic Platform plan: **Security + Cost** pillars, cross-account IAM role onboarding, async audits via Redis/RQ, LangGraph orchestration, and Next.js UI.

## Architecture

Stack overview (services, data stores, and how traffic flows through the platform):

![Architecture diagram](Architecture-diagram.png)

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
# Edit `.env`: set AUDIT_API_KEY and AWS credentials if you use verify / real audits.
```

See **Local development (full stack on the host)** below for the exact order to start Postgres, API, UI, and worker.

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

## Local development (full stack on the host)

Use this flow for **fast iteration**: API and Next.js reload on save; only the worker needs a manual restart when you change worker/collector/rule code.

You do **not** need `npm run build` or `next start` for everyday UI work.

### Prerequisites

- **Docker** running (Docker Desktop, Colima, etc.) — only for Postgres and Redis.
- **Python** and **Node** versions matching `audit-api/pyproject.toml` and `audit-frontend/package.json`.

### Step 1 — One-time: virtualenv and editable installs

From the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate                    # Windows Git Bash: source .venv/Scripts/activate
pip install -U pip
pip install -e ./audit-core -e ./audit-data-collection -e ./audit-agents -e "./audit-api[dev]"
```

Keep this terminal (or any terminal) with the venv activated for Python commands below.

### Step 2 — Environment files

1. **Repo template:** `cp .env.example .env` at the repo root and edit values (database, Redis, API key, AWS region/credentials if you verify accounts or run audits).
2. **API layered `.env`:** `audit-api` reads **`./.env`** then **`audit-api/.env`** (later file overrides). Either root `.env` alone or `audit-api/.env` alone is fine if variables are set.
3. **Frontend proxy:** create **`audit-frontend/.env.local`** so server-side routes can call the API with the correct key:

```env
AUDIT_API_URL=http://127.0.0.1:8000
AUDIT_API_KEY=dev-change-me
```

`AUDIT_API_KEY` must match the API (`AUDIT_API_KEY` / `audit_api_key` in `audit_api/settings.py`; default **`dev-change-me`**). Restart `npm run dev` after changing `.env.local`.

4. **Worker:** `python -m audit_agents.worker` loads env from **`./.env`**, **`audit-agents/.env`**, **`audit-agents/audit_agents/.env`**, then **`audit-api/.env`** (same layering idea as the API: later files win on duplicate keys). **Variables already set in your shell are never overwritten.** Empty values in files are ignored so placeholder keys do not block boto3. Put **`AWS_ACCESS_KEY_ID`** / **`AWS_SECRET_ACCESS_KEY`** (and optional **`AWS_SESSION_TOKEN`**) in **`audit-api/.env`** or the repo **`.env`** so the worker uses the **same platform principal** as the API — otherwise boto3 may fall back to **`~/.aws/credentials`**. If `REDIS_URL` is still unset, it defaults to **`redis://localhost:6379/0`**. If `RULE_PACK_PATH` / `ARTIFACTS_DIR` are unset, defaults are **`<repo>/rule_packs/v1`** and **`<system temp>/audit-artifacts`**. Align **`DATABASE_URL`** / **`REDIS_URL`** with the API so both use the same Postgres and Redis.

### Step 3 — Start Postgres and Redis

Use a **dedicated terminal** (add `-d` to run in the background):

```bash
docker compose up postgres redis
```

Wait until Postgres accepts connections. Defaults match `.env.example`: `audit` / `audit` on **`localhost:5432`**, Redis on **`localhost:6379`**.

### Step 4 — Start the API (auto-reload)

With `.venv` activated:

```bash
cd audit-api
uvicorn audit_api.main:app --reload --host 127.0.0.1 --port 8000
```

The API runs **`init_db()`** on startup, so you do not need a separate migration step for the MVP schema.

### Step 5 — Start the Next.js dev server

```bash
cd audit-frontend
npm install    # first time only
npm run dev
```

Open **http://localhost:3000**.

### Step 6 — Start the RQ worker (required for scans)

The API **only enqueues** jobs to Redis. Without a worker, runs stay **`queued`**; the UI shows **Queued** and **no duration timer** until the worker sets status to **running** and **`started_at`**.

From the **repo root**, with the same `.venv` activated:

```bash
source .venv/bin/activate    # Windows Git Bash: source .venv/Scripts/activate
python -m audit_agents.worker
```

There is **no** `--reload` on the worker. After you change code under **`audit-agents/`**, **`audit-data-collection/`**, **`audit-core/`**, or **`rule_packs/`**, stop the worker (**Ctrl+C**) and start it again. Postgres/Redis do not need restarts for code-only edits.

**Windows vs Linux (production):** RQ’s default **`Worker`** forks a child per job and uses **`SIGALRM`** for timeouts — both require Unix-like OS support. **Docker images run Linux** and keep that default behavior; there is no Windows-specific code path in containers.

For **local development on Windows only**, `python -m audit_agents.worker` selects **`WindowsSimpleWorker`**: jobs run **in-process** (no `fork`) and use RQ’s **`TimerDeathPenalty`** instead of **`SIGALRM`**. macOS/Linux shells still use the standard forking **`Worker`**.

Do not rely on Windows for production parity testing of hard job timeouts or process isolation — validate those in Linux/Docker.

#### Worker environment variables (reference)

| Variable | Required? | Purpose |
|----------|-----------|---------|
| `DATABASE_URL` | Default OK locally | Same Postgres as the API (`audit_core` defaults to `postgresql+psycopg://audit:audit@localhost:5432/audit` if unset). |
| `REDIS_URL` | Default OK locally | Same Redis as the API; defaults to **`redis://localhost:6379/0`** if unset after `.env` loading. |
| `RULE_PACK_PATH` | Default OK locally | YAML rules; defaults to **`<repo>/rule_packs/v1`**. |
| `ARTIFACTS_DIR` | Default OK locally | Writable directory for HTML reports; defaults to **`<temp>/audit-artifacts`**. |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | **Yes for real audits** | Same platform principal as the API (`sts:AssumeRole`). Optional if you never run a scan. |
| `AWS_DEFAULT_REGION` | Recommended | e.g. `us-east-1`. |
| `AUDIT_LLM_URL` | No | Optional summarize step; omit or point at `http://127.0.0.1:8001` if you run the LLM stub. |
| `AUDIT_JOB_TIMEOUT_SECONDS` | No | RQ job timeout; Compose worker uses 900s unless overridden. |

**Optional explicit exports (bash)** — only if you do not use `.env` files:

```bash
source .venv/bin/activate
export DATABASE_URL=postgresql+psycopg://audit:audit@127.0.0.1:5432/audit
export REDIS_URL=redis://127.0.0.1:6379/0
export RULE_PACK_PATH=/absolute/path/to/aws-account-auditor/rule_packs/v1
export ARTIFACTS_DIR=/tmp/audit-artifacts
export AWS_DEFAULT_REGION=us-east-1
python -m audit_agents.worker
```

### Step 7 — Optional: LLM stub

If you want the summarize step to hit the stub instead of skipping it, expose **`http://127.0.0.1:8001`** and set **`AUDIT_LLM_URL=http://127.0.0.1:8001`** (repo `.env` or worker layered `.env`).

**Compose (simplest):**

```bash
docker compose up audit-llm
```

**Fully on the host** (add **`pip install -e ./audit-llm`** once in Step 1 if you use this path):

```bash
source .venv/bin/activate
uvicorn audit_llm.main:app --host 127.0.0.1 --port 8001
```

### Step 8 — Sanity checks

- **API docs:** http://127.0.0.1:8000/docs  
- **Dashboard:** http://localhost:3000  
- Enqueue a scan from the UI; confirm the worker logs job activity and the run moves from **Queued** to **Running**, then completes.

**Troubleshooting**

- **`GET /api/backend/accounts` 401:** mismatch between `audit-frontend/.env.local` and API `AUDIT_API_KEY`.  
- **Run stuck Queued:** worker not running, or **`REDIS_URL`** / **`DATABASE_URL`** differ between API and worker (or Redis not up).  
- **`python -m audit_agents.worker` can’t connect to Redis:** start **`docker compose up postgres redis`** and ensure **`REDIS_URL`** matches published **`localhost:6379`**.

### Hybrid: DB/Redis/worker in Docker, API + frontend on the host

To avoid running the worker manually but keep fast API/UI reload:

```bash
docker compose up postgres redis audit-worker audit-llm
```

Then run **uvicorn** (Step 4) and **`npm run dev`** (Step 5) on the host. Ensure **`DATABASE_URL` / `REDIS_URL`** on the host API point at **`localhost:5432`** and **`localhost:6379`** (published ports). Your **AWS credentials** must still be available to whichever process runs **`audit-worker`** (the Compose worker uses `.env` — pass **`docker compose --env-file .env up …`**).

### What to restart for local changes

| You changed | Restart |
|-------------|---------|
| `audit-frontend/` | Usually nothing (Vite/Next HMR). Restart `npm run dev` if env files change. |
| `audit-api/` | Nothing if using `uvicorn --reload`; otherwise restart uvicorn. |
| `audit-agents/`, `audit-data-collection/`, `audit-core/`, `rule_packs/` | **Restart the worker** (and rebuild Docker image only if the worker runs in Compose and you changed Dockerfile). |
| Postgres schema / data | Migrations / `init_db` only; rarely restart DB. |

**URLs:** dashboard http://localhost:3000 · OpenAPI http://127.0.0.1:8000/docs  

**Symptom:** run stays **Queued** and never moves to **Running** → worker not running, Redis down, or **`REDIS_URL` / `DATABASE_URL`** mismatch between API and worker.

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

