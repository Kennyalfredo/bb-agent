---
description: Active GraphQL security hunt for an ingested program. Tests introspection exposure, authorization bypass, query batching abuse, injection through arguments (SQLi/NoSQLi/SSTI/SSRF), and depth/complexity limits via Burp MCP. Confirms to the proof ceiling (demonstrate misconfiguration/data leak for bug_bounty; extend to data-access scope for contracted_pentest — never exfiltrate real user data, never DoS, never mutate beyond own account). Writes redacted candidates; does not verify ownership or draft.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off active GraphQL security hunting for program slug: $ARGUMENTS

Delegate to the `graphql-hunter` subagent. Require it to:
1. Read `.claude/skills/webvuln-compliance/SKILL.md` + `memory/programs/<slug>.json`; apply the §1 hard gate (**REFUSE** + empty-candidates output with `refused_reason` on `automated_tools_allowed==false` / `explicit_scanner_ban==true` / out-of-scope). Confirm Burp MCP reachable.
2. Require `out/<slug>/webvuln/surface/*.json` (run `/webvuln-surface` first). Auth-context at `/mnt/files/bb-agent/<slug>/webvuln/auth/context.json` is strongly recommended — most GraphQL auth testing requires a valid token for comparison. Without it, only unauthenticated testing runs (note `unauth_only=true`).
3. Apply the **offensive-graphql** skill methodology under the compliance gate.
4. Read the structured payload bank (`_resources/payloads/graphql.json`). Test GraphQL endpoints systematically by phase:
   - **Phase 0 discovery** (probe common paths, fingerprint implementation) → **Phase 1 introspection** (full/partial schema dump, field suggestion probing, sensitive field analysis) → **Phase 2 auth bypass** (unauth access, role escalation, Hasura header injection, method/content-type bypass, expired token, IDOR pattern on OWN account) → **Phase 3 batching abuse** (array + alias batching, max 5 queries proof) → **Phase 4 injection** (SQLi/NoSQLi/SSRF/SSTI/cmdi via arguments and variables, OWN account mutations only) → **Phase 5 DoS probe** (depth 3→5→7 timing measurement, ONE attempt at max depth, alias/pagination limit check).
   Apply suspicion scoring (0–100) with engagement-type-aware thresholds.
   **Proof ceiling: demonstrate misconfiguration/auth bypass/data leak — then STOP.** No bulk data exfiltration, no other-user data access, no production mutations beyond own account, no DoS beyond one depth-7 probe. Honor `rate_limit_cap_rps` (default 2 r/s). Track every payload id as tested/hit/blocked/skipped.
5. Write `out/<slug>/webvuln/graphql/<UTC-ts>.json` (redacted; raw evidence 0700 under `/mnt/files`).

When the subagent returns, relay:
- the funnel: `hosts_probed → endpoints_found → schema_analyzed → auth_tested → confirmed by type (introspection / auth_bypass / injection / batching / depth)` + enforced-negative count,
- `unauth_only` status,
- implementation identified (Apollo/Hasura/graphene/etc.),
- sensitive fields summary (credential/PII/internal/admin fields exposed),
- top confirmed findings as `type @ endpoint (severity=, confidence=)` with one-line redacted proof,
- the literal next steps per confirmed host: `/verify-ownership <slug> <host>`, then `/draft-report <slug> <host-or-asset>`.

Reminder to the user: **proof ceiling respected — demonstrated misconfiguration/auth bypass only. No bulk data exfiltration, no other-user data, no production mutations beyond own account, no DoS.** report-drafter caps severity to `scope.severity_cap`; **no auto-submit** — human reviews, pastes, then `/outcome` closes the loop.
