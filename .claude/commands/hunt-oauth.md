---
description: Active OAuth 2.0/OIDC hunt for an ingested program. Tests redirect_uri bypass, state/CSRF, scope escalation, token leakage, and PKCE bypass via Burp MCP. Confirms to the proof ceiling (demonstrate redirect/leak with a benign sink — never steal another user's token/code, never complete ATO). Writes redacted candidates; does not verify ownership or draft.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off active OAuth hunting for program slug: $ARGUMENTS

Delegate to the `oauth-hunter` subagent. Require it to:
1. Read `.claude/skills/webvuln-compliance/SKILL.md` + `memory/programs/<slug>.json`; apply the §1 hard gate (**REFUSE** + empty-candidates output with `refused_reason` on `automated_tools_allowed==false` / `explicit_scanner_ban==true` / out-of-scope). Confirm Burp MCP reachable.
2. Require `out/<slug>/webvuln/surface/*.json` (run `/webvuln-surface` first). Auth-context at `/mnt/files/bb-agent/<slug>/webvuln/auth/context.json` is **strongly recommended** — OAuth testing requires authenticated sessions to observe and manipulate flows. Without it, only Phase 0 discovery runs (note `unauth_only=true`).
3. Apply the **offensive-oauth** skill methodology under the compliance gate.
4. Read the structured payload bank (`_resources/payloads/oauth.json`). Test OAuth flows ranked by tier (tier1: implicit flow → tier5: device code), iterating payloads systematically by phase:
   - Phase 0 discovery (identify flows, endpoints, providers, configuration) → Phase 1 redirect_uri manipulation (external domain, subdomain swap, path traversal, scheme downgrade, open redirect chains) → Phase 2 state/CSRF (missing state, replay, cross-session, nonce) → Phase 3 scope escalation (elevated scopes, refresh token exchange) → Phase 4 token/code leak (Referer leak, code replay, code expiry, client_secret bypass) → Phase 5 PKCE bypass (missing verifier, wrong verifier, downgrade to plain).
   Apply suspicion scoring (0–100) with engagement-type-aware thresholds.
   **Proof ceiling: demonstrate redirect/leak with a benign sink (Collaborator/controlled domain) — then STOP.** Never steal another user's code/token, never complete ATO, no phishing, no social engineering. Honor `rate_limit_cap_rps` (default 2 r/s). Track every payload id as tested/hit/blocked/skipped.
5. Write `out/<slug>/webvuln/oauth/<UTC-ts>.json` (redacted; raw evidence 0700 under `/mnt/files`).

When the subagent returns, relay:
- the funnel: `flows_detected → flows_tested → confirmed by type (redirect / state / scope / leak / pkce)` + enforced-negative count,
- `unauth_only` status,
- OAuth providers and flow types identified,
- top confirmed findings as `type @ url (severity=, confidence=)` with one-line redacted proof,
- the literal next steps per confirmed host: `/verify-ownership <slug> <host>`, then `/draft-report <slug> <host-or-asset>`.

Reminder to the user: **proof ceiling respected — redirect/leak demonstrated with benign sink only. No other user's code/token stolen, no ATO completed.** report-drafter caps severity to `scope.severity_cap`; **no auto-submit** — human reviews, pastes, then `/outcome` closes the loop.
