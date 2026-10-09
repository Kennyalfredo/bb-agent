---
description: Store + validate authenticated test-account credentials for the active web-vuln tier. Paste session material (cookies / bearer / headers) for one or two in-scope test accounts plus a benign validation endpoint; the agent confirms each is live and stores it 0600 off-repo. Two accounts unlock cross-account IDOR/BOLA.
argument-hint: <program-slug>  (then paste auth material + a benign in-scope GET endpoint)
allowed-tools: Agent
---

You are loading authenticated test-account context for program slug: $ARGUMENTS

If the operator hasn't already pasted the auth material, ask for:
1. **Account A** session material — a `Cookie:` value and/or `Authorization: Bearer <jwt>` and any extra headers.
2. **(Optional but recommended) Account B** — a second test account's material. Two accounts are required for cross-account IDOR/BOLA; with one you get only forced-browsing/BFLA + same-account checks.
3. A **benign validation endpoint** — an in-scope authenticated GET that returns 200 when logged in (e.g. `https://app.example.com/api/me`).

Then delegate to the `auth-context` subagent. Require it to:
1. Read `.claude/skills/webvuln-compliance/SKILL.md` + `memory/programs/<slug>.json`; apply the §1 gate; confirm the validation host is under an in-scope wildcard/domain (refuse otherwise).
2. Send exactly ONE benign Burp request per account to the validation endpoint; record authenticated status + response-shape KEYS only (never values).
3. Write `/mnt/files/bb-agent/<slug>/webvuln/auth/context.json` at mode 0600 (dir 0700) — off-repo, never under git.
4. Never echo raw cookies/tokens — `<first-4>…<last-4>` only.

When the subagent returns, relay (no secrets):
- which accounts validated (`account_a: 200 ✓` / `account_b: 401 ✗ expired`),
- whether two valid accounts are present (cross-account IDOR available y/n),
- the 0600 storage path + the reminder that sessions are time-limited (re-run `/auth-load` when they expire),
- the literal next step: `/webvuln-surface <slug>` then `/hunt-access <slug>`.
