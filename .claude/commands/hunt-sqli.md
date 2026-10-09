---
description: Active SQL injection hunt for an ingested program. Runs sqlmap smart pre-scan as fast bulk triage, then confirms/extends via Burp with manual payload-bank probing (error-based, boolean-blind, time-blind, UNION). Confirms to the proof ceiling (boolean-diff / time-delay / version read — never dump tables, never write). Writes redacted candidates; does not verify ownership or draft.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off active SQL injection hunting for program slug: $ARGUMENTS

Delegate to the `sqli-hunter` subagent. Require it to:
1. Read `.claude/skills/webvuln-compliance/SKILL.md` + `memory/programs/<slug>.json`; apply the §1 hard gate (**REFUSE** + empty-candidates output with `refused_reason` on `automated_tools_allowed==false` / `explicit_scanner_ban==true` / out-of-scope). Confirm Burp MCP is reachable.
2. Require `out/<slug>/webvuln/surface/*.json` (run `/webvuln-surface` first). Auth-context at `/mnt/files/bb-agent/<slug>/webvuln/auth/context.json` is optional — without it, only unauthenticated endpoints are tested (note `unauth_only=true`).
3. Apply the **offensive-sqli** skill methodology under the compliance gate.
4. Read the structured payload bank (`_resources/payloads/sqli.json`). Detect SQL context per injection point (numeric, string_sq, order_by, like_clause, json_field). Test injection points ranked by tier (tier1: auth+json_array → tier5: unranked), iterating payloads systematically by phase:
   - **Phase S sqlmap smart pre-scan** (fast bulk triage via `sqlmap --smart --technique=BET --level=1 --risk=1`, rate-limited) → Phase 1 error-based (skipped for sqlmap-confirmed) → Phase 2 boolean-blind → Phase 3 time-blind → Phase 4 UNION (confirmed only, including sqlmap-confirmed needing version proof) → Phase 5 WAF bypass (one round) → Phase 6 **sqlmap targeted deep confirmation** (manually-discovered confirmed/high-suspicion only, NOT Phase-S-confirmed — `sqlmap -r <req> -p <param> --technique=<match> --batch --banner --current-db --level=1 --risk=1`; NEVER `--dump`/`--os-shell`) → Phase 7 NoSQL (if MongoDB/CouchDB suspected).
   sqlmap Phase S confirmed findings skip manual phases 1–3 (fast path). Phase S heuristic-positives get priority boost through manual phases. Phase 6 deep confirmation only targets manually-discovered candidates.
   **Proof ceiling: boolean-diff / time-delay / version() or @@version read — then STOP.** No schema enumeration, no table dump, no data extraction, no writes, no OS command exec. Honor `rate_limit_cap_rps` (default 2 r/s). Track every payload id as tested/hit/blocked/skipped.
5. Write `out/<slug>/webvuln/sqli/<UTC-ts>.json` (redacted; raw evidence 0700 under `/mnt/files`).

When the subagent returns, relay:
- the funnel: `seeds → sqlmap-prescan → candidates_tested → confirmed by technique (error / boolean_blind / time_blind / union)` + sqlmap prescan stats (confirmed/heuristic) + enforced-negative count + waf_blocked count,
- `unauth_only` status (true = no auth-context, partial coverage),
- DB engines identified from errors/version reads,
- top confirmed findings as `technique @ url:param (severity=, confidence=)` with the one-line redacted proof,
- the literal next steps per confirmed host: `/verify-ownership <slug> <host>` (the `in_scope_subdomain_override` auto-fires for in-scope wildcards), then `/draft-report <slug> <host-or-asset>`.

Reminder to the user: **proof ceiling respected — boolean-diff / time-delay / version read only. No schema enumeration, no data extraction, no writes.** report-drafter caps severity to `scope.severity_cap`; **no auto-submit** — human reviews, pastes, then `/outcome` closes the loop.
