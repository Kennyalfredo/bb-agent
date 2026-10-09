---
description: Active race condition / TOCTOU hunt for an ingested program. Tests single-endpoint duplicate actions (double-spend, coupon reuse, vote stuffing), multi-endpoint state races (check-then-use, email+reset), timing analysis, and rate-limit bypass via concurrent Burp requests (single-packet attack / last-byte sync). Confirms to the proof ceiling (minimum concurrent requests to show the race — never repeat for material gain, never cause financial harm, never mass-create records beyond proof). Writes redacted candidates; does not verify ownership or draft.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off active race condition hunting for program slug: $ARGUMENTS

Delegate to the `race-hunter` subagent. Require it to:
1. Read `.claude/skills/webvuln-compliance/SKILL.md` + `memory/programs/<slug>.json`; apply the §1 hard gate (**REFUSE** + empty-candidates output with `refused_reason` on `automated_tools_allowed==false` / `explicit_scanner_ban==true` / out-of-scope). Confirm Burp MCP reachable.
2. Require `out/<slug>/webvuln/surface/*.json` (run `/webvuln-surface` first). Auth-context at `/mnt/files/bb-agent/<slug>/webvuln/auth/context.json` is **STRONGLY RECOMMENDED** — race condition testing is severely limited without authenticated sessions.
3. Apply the **offensive-race-condition** skill methodology under the compliance gate.
4. Read the structured payload bank (`_resources/payloads/race.json`). Test state-changing endpoints ranked by tier (tier1: financial+auth → tier6: remaining POST), iterating techniques systematically by phase:
   - **Phase 0 endpoint classification** (idempotency check, duplicate protection detection) → Phase 1 single-endpoint race (N=5 concurrent identical requests via single-packet attack; escalate to N=10 on signal) → Phase 2 multi-endpoint race (paired endpoints hitting same state simultaneously) → Phase 3 timing analysis (response variance under concurrent load, DB error detection) → Phase 4 limit bypass (rate limit burst, lockout bypass, OTP/CAPTCHA reuse).
   Apply suspicion scoring (0–100) with engagement-type-aware thresholds. Concurrency capped at N=20 absolute.
   **Proof ceiling: minimum concurrent requests to show the race exists — then STOP.** No material gain, no financial harm, no mass duplication (2–3 max), no targeting other users, no DoS via resource exhaustion. Only test own accounts. Honor `rate_limit_cap_rps` between batches. Track every technique id as tested/hit/blocked/skipped/not_applicable.
5. Write `out/<slug>/webvuln/race/<UTC-ts>.json` (redacted; raw evidence 0700 under `/mnt/files`).

When the subagent returns, relay:
- the funnel: `seeds → state_changing_endpoints → candidates_tested → confirmed by type (double_spend / duplicate_action / limit_bypass / state_inconsistency / token_reuse)` + enforced-negative count,
- `unauth_only` status,
- max concurrency used and techniques (single-packet / last-byte),
- top confirmed findings as `type @ url (severity=, confidence=, N=concurrency)` with one-line redacted proof,
- the literal next steps per confirmed host: `/verify-ownership <slug> <host>`, then `/draft-report <slug> <host-or-asset>`.

Reminder to the user: **proof ceiling respected — minimum concurrent requests to demonstrate the race. No material gain, no financial harm, no mass duplication. Concurrency capped at N=20.** report-drafter caps severity to `scope.severity_cap`; **no auto-submit** — human reviews, pastes, then `/outcome` closes the loop.
