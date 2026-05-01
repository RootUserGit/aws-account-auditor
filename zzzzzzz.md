# Audit API — direct HTTP examples

Base URL with Docker Compose (host machine): **`http://localhost:8000`**

All routes except **`GET /health`** require header:

```http
X-API-Key: <same value as AUDIT_API_KEY for audit-api>
```

Default in compose when **`AUDIT_API_KEY` is not set** in your env file: **`dev-change-me`** (no leading dash — not `-dev-change-me`).

### Common mistake: using the variable *name* as the key

`AUDIT_API_KEY` is only the **name** of the environment variable. In `curl`, you must send whatever **value** appears after `=` in your env file (or the default above).

Examples:

| Your setup | Value to send in `X-API-Key` |
|------------|------------------------------|
| `.env` / `.env.example` has `AUDIT_API_KEY=change-me-in-production` | `change-me-in-production` |
| No `AUDIT_API_KEY` in env file (compose uses default) | `dev-change-me` |
| Wrong | Literally `AUDIT_API_KEY` or `-dev-change-me` |

There is **no HTTP endpoint** that returns the API key (that would defeat the purpose). To see what the **audit-api container** is actually using:

```bash
docker compose --env-file .env.example exec audit-api printenv AUDIT_API_KEY
```

(Use the same `--env-file` you use for `up`.)

---

## Health (no API key)

```bash
curl -sS http://localhost:8000/health
```

---

## Accounts

### List onboarded accounts

```bash
curl -sS http://localhost:8000/accounts \
  -H "X-API-Key: YOUR_AUDIT_API_KEY"
```

### Register an AWS account (row in DB)

```bash
curl -sS -X POST http://localhost:8000/accounts \
  -H "X-API-Key: YOUR_AUDIT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "123456789012",
    "role_arn": "arn:aws:iam::123456789012:role/YourAuditorRole",
    "external_id": "your-external-id-min-8-chars"
  }'
```

### Verify STS AssumeRole (platform credentials must be configured on API)

```bash
# account_id here is the UUID row id from POST /accounts, not the 12-digit AWS account id
curl -sS -X POST "http://localhost:8000/accounts/<ACCOUNT_UUID>/verify" \
  -H "X-API-Key: YOUR_AUDIT_API_KEY"
```

### Delete account (cascades runs / findings / artifacts for that account)

```bash
curl -sS -X DELETE "http://localhost:8000/accounts/<ACCOUNT_UUID>" \
  -H "X-API-Key: YOUR_AUDIT_API_KEY"
```

### Start an audit run

```bash
curl -sS -X POST "http://localhost:8000/accounts/<ACCOUNT_UUID>/runs" \
  -H "X-API-Key: YOUR_AUDIT_API_KEY"
```

Response includes `run_id` (UUID string) and initial `status` (e.g. `queued`).

---

## Runs

Replace `<RUN_UUID>` with the value returned from `POST .../runs`.

### Get run status and summary

```bash
curl -sS "http://localhost:8000/runs/<RUN_UUID>" \
  -H "X-API-Key: YOUR_AUDIT_API_KEY"
```

Terminal statuses: `succeeded`, `failed`. When finished, `finished_at` is non-null.

### List findings for a run

```bash
curl -sS "http://localhost:8000/runs/<RUN_UUID>/findings?limit=500" \
  -H "X-API-Key: YOUR_AUDIT_API_KEY"
```

Optional query params: `skip`, `limit` (1–500), `pillar`, `severity`.

### Get one finding (evidence + remediation)

Use the finding `id` from the list response (UUID).

```bash
curl -sS "http://localhost:8000/runs/<RUN_UUID>/findings/<FINDING_UUID>" \
  -H "X-API-Key: YOUR_AUDIT_API_KEY"
```

### Download HTML report (when artifact exists)

```bash
curl -sS -o report.html "http://localhost:8000/runs/<RUN_UUID>/report.html" \
  -H "X-API-Key: YOUR_AUDIT_API_KEY"
```

---

## Quick reference

| Method | Path | Notes |
|--------|------|--------|
| GET | `/health` | No auth |
| GET | `/accounts` | List |
| POST | `/accounts` | JSON body `AwsAccountCreate` |
| POST | `/accounts/{account_id}/verify` | UUID row id |
| DELETE | `/accounts/{account_id}` | UUID row id |
| POST | `/accounts/{account_id}/runs` | Returns `run_id` |
| GET | `/runs/{run_id}` | Run metadata |
| GET | `/runs/{run_id}/findings` | Query: `limit`, `skip`, `pillar`, `severity` |
| GET | `/runs/{run_id}/findings/{finding_id}` | Single finding (includes `evidence_json`) |
| GET | `/runs/{run_id}/report.html` | Binary/HTML file |

---

## Same calls via Next.js proxy (optional)

If the UI is running on port 3000, equivalent URLs are under **`http://localhost:3000/api/backend/...`** (path after `/api/backend/` matches the API path above). The proxy injects `X-API-Key` from server env — useful for browsers, not required for direct `curl` to port 8000.
