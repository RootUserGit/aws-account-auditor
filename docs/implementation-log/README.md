# Implementation log

Use this folder to record **what shipped in the repo** each time we merge or prepare a push: features, rule changes, API/worker behavior, and bug fixes.

## Convention

- **One file per calendar day** (or per release day) when work lands: `YYYY-MM-DD.md`.
- Append sections under that day as you commit; keep the newest bullets at the **bottom** of the day’s file, or group by area (frontend, API, rules, …)—pick one style per file and stay consistent.
- Prefer **specific** entries: file paths, endpoint paths, rule IDs, and the user-visible outcome—not vague summaries.
- If a change is reverted the same day, add a bullet noting the revert.

## Index

| Date       | File           | Notes                          |
| ---------- | -------------- | ------------------------------ |
| 2026-05-02 | `2026-05-02.md` | Rule pack expansion, scan UX, dashboard charts, findings UX |
