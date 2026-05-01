# Contracts

- HTTP APIs are defined by FastAPI's automatic OpenAPI at `/openapi.json` on `audit-api` and `/openapi.json` on `audit-llm`.
- JSON payloads for `Finding`, `AuditRun`, and queue job bodies should stay backward compatible; bump versions when breaking.

Place hand-written fragments here when you split repositories and need published artifacts.
