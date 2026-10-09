---
description: Active JWT authentication bypass hunt for an ingested program. Tests algorithm manipulation (alg:none, RS256→HS256 confusion), weak HMAC secrets, signature bypass (jwk/jku/x5u injection), claim tampering (privilege escalation on OWN account only), and kid parameter injection. Confirms to the proof ceiling (forge token accepted for your own account — never ATO another user). Writes redacted candidates; does not verify ownership or draft.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off active JWT hunting for program slug: $ARGUMENTS

Delegate to the `jwt-hunter` subagent. Require it to:
1. Read `.claude/skills/webvuln-compliance/SKILL.md` + `memory/programs/<slug>.json`; apply the §1 hard gate (**REFUSE** + empty-candidates output with `refused_reason` on `automated_tools_allowed==false` / `explicit_scanner_ban==true` / out-of-scope). Confirm Burp MCP reachable.
2. Require `out/<slug>/webvuln/surface/*.json` (run `/webvuln-surface` first). Auth-context at `/mnt/files/bb-agent/<slug>/webvuln/auth/context.json` is **required** — JWT testing needs authenticated sessions. Without it, refuse with `refused_reason`.
3. Apply the **offensive-jwt** skill methodology under the compliance gate.
4. Read the structured payload bank (`_resources/payloads/jwt.json`). Test JWT tokens found in traffic, iterating payloads systematically by phase:
   - Phase 0 detection (passive JWT discovery, decode, JWKS enumeration) → Phase 1 algorithm manipulation (alg:none variants, 50-entry weak secret dictionary) → Phase 2 signature bypass (empty/null sig, jwk/jku/x5u injection) → Phase 3 claim tampering (expiration, iss/aud, role/admin/scope escalation **on OWN account ONLY**) → Phase 4 kid injection (directory traversal to /dev/null, SQLi, command injection) → Phase 5 key confusion (RS256→HS256 with public key as HMAC secret, x5c injection).
   Apply suspicion scoring (0–100) with engagement-type-aware thresholds.
   **Proof ceiling: forge a token accepted for YOUR OWN account — then STOP.** No ATO, no other-user impersonation, no brute-force beyond the 50-entry dictionary, no sensitive file reads via kid traversal, no destructive commands. Honor `rate_limit_cap_rps` (default 2 r/s). Track every payload id as tested/hit/blocked/skipped.
5. Write `out/<slug>/webvuln/jwt/<UTC-ts>.json` (redacted; raw evidence 0700 under `/mnt/files`).

When the subagent returns, relay:
- the funnel: `jwt_locations_found → phases_tested → confirmed by type (alg_none / weak_secret / sig_bypass / claim_escalation / kid_injection / key_confusion)` + enforced-negative count,
- algorithms and header parameters encountered,
- JWKS endpoint availability,
- top confirmed findings as `technique @ url (severity=, confidence=)` with one-line redacted proof,
- the literal next steps per confirmed host: `/verify-ownership <slug> <host>`, then `/draft-report <slug> <host-or-asset>`.

Reminder to the user: **proof ceiling respected — token forged for OWN account only. No ATO, no other-user impersonation, no brute-force beyond 50-entry dictionary.** report-drafter caps severity to `scope.severity_cap`; **no auto-submit** — human reviews, pastes, then `/outcome` closes the loop.
