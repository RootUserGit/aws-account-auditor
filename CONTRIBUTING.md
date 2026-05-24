# Contributing Guidelines

## Workflow
1. Fork the repo
2. Create a branch:
   - feature/*
   - bugfix/*
3. Commit changes with clear messages
4. Push and create a Pull Request

## Rules
- Do NOT push directly to main
- PR must be approved before merge
- CI/CD checks must pass

## Code Style
- Follow existing project structure
- Write clean, readable code
- Add comments where necessary

## Security & static analysis (professional bar)
Tools such as CodeQL flag **building executable code from interpolated strings**
even when values look “obviously” constant. That is intentional: tomorrow the
value might come from config, env, or an API.

**Do**
- Treat inline `<script>` / `dangerouslySetInnerHTML` as **untrusted output
  channels**: escape for both **HTML** (`</script>`, `<`, `>`) and **JS line
  grammar** (e.g. U+2028 / U+2029) when embedding serialized data.
- Prefer **no inline script** when a framework hook or `<Script>` strategy is
  enough; when you must inline, document why and centralize sanitization.
- Run `npm audit` / CI security jobs and fix findings rather than dismissing
  alerts without a documented exception.

**Avoid**
- “It’s only a constant” as the sole justification for skipping sanitization.
- Copy-pasting minified script blobs without a maintainable escape path.

Aim for code that passes review **and** automated security rules without
special pleading—clear, boring, and defensible.

## Commit Convention
- feat: new feature
- fix: bug fix
- docs: documentation

Example:
feat: add AWS audit module
