---
description: Active XSS hunt for an ingested program. Runs Dalfox bulk pre-filter, then confirms via Burp MCP + Playwright with context-aware payloads. Handles reflected/stored/DOM/blind XSS to the proof ceiling (alert(document.domain) in own session — never stored XSS for other users, never cookie exfil). Writes redacted candidates; does not verify ownership or draft.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off active XSS hunting for program slug: $ARGUMENTS

Delegate to the `xss-hunter` subagent. Require it to:
1. Read `.claude/skills/webvuln-compliance/SKILL.md` + `memory/programs/<slug>.json`; apply the §1 hard gate (**REFUSE** + empty-candidates output with `refused_reason` on `automated_tools_allowed==false` / `explicit_scanner_ban==true` / out-of-scope). Confirm Burp MCP + Playwright reachable.
2. Require `out/<slug>/webvuln/surface/*.json` (run `/webvuln-surface` first). Auth-context at `/mnt/files/bb-agent/<slug>/webvuln/auth/context.json` is optional — without it, only unauthenticated endpoints are tested (note `unauth_only=true`).
3. Apply the **offensive-xss** skill methodology under the compliance gate.
4. Read the structured payload bank (`_resources/payloads/xss.json`). Test injection points ranked by tier (tier1: reflected+html+no-CSP → tier5: unranked), iterating payloads systematically by phase:
   - **Phase D Dalfox bulk pre-filter** (fast triage of all GET-param URLs via `~/go/bin/dalfox`, `--only-discovery`, rate-limited) → Phase 0 canary probe (detect reflection + context; skipped for Dalfox-verified params) → Phase 1 basic context-aware payloads → Phase 2 filter profiling → Phase 3 WAF/filter bypass (one round) → Phase 4 DOM XSS via Playwright (sink/source analysis) → Phase 5 stored XSS (own accounts only; blind XSS in contracted_pentest posture).
   Dalfox `V` findings go to fast-path Playwright confirmation; `R` findings skip canary. Verify execution via Playwright (`browser_console_messages` / dialog detection). Apply suspicion scoring (0–100, Phase D scores included) with engagement-type-aware thresholds.
   **Proof ceiling: alert(document.domain) in own session — then STOP.** No cookie exfil to external server (Collaborator callback for blind proof allowed on own data), no stored XSS affecting other users, no session hijack. Honor `rate_limit_cap_rps` (default 2 r/s). Track every payload id as tested/hit/blocked/skipped.
5. Write `out/<slug>/webvuln/xss/<UTC-ts>.json` (redacted; raw evidence 0700 under `/mnt/files`).

When the subagent returns, relay:
- the funnel: `seeds → dalfox-prescan → reflected → context-detected → tested → confirmed by type (reflected / stored / dom / blind)` + Dalfox verified/reflected counts + CSP-mitigated count + WAF-blocked count,
- `unauth_only` status,
- reflection contexts found (html_body, html_attr, js_string, etc.),
- top confirmed findings as `type @ url:param (severity=, confidence=)` with one-line redacted proof,
- the literal next steps per confirmed host: `/verify-ownership <slug> <host>`, then `/draft-report <slug> <host-or-asset>`.

Reminder to the user: **proof ceiling respected — alert(document.domain) in own session only. No cookie exfil, no stored XSS for other users.** report-drafter caps severity to `scope.severity_cap`; **no auto-submit** — human reviews, pastes, then `/outcome` closes the loop.
