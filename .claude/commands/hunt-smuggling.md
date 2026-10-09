---
description: Active HTTP request smuggling hunt for an ingested program. Tests CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, CL.0, and h2c upgrade desync variants via Burp MCP. Confirms to the proof ceiling (timing + differential on your OWN requests for bug_bounty; extends to self-impact like response queue poisoning or test-path cache poisoning for contracted_pentest — never poison other users, never DoS). Writes redacted candidates; does not verify ownership or draft.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off active HTTP request smuggling hunting for program slug: $ARGUMENTS

Delegate to the `smuggling-hunter` subagent. Require it to:
1. Read `.claude/skills/webvuln-compliance/SKILL.md` + `memory/programs/<slug>.json`; apply the §1 hard gate (**REFUSE** + empty-candidates output with `refused_reason` on `automated_tools_allowed==false` / `explicit_scanner_ban==true` / out-of-scope). Confirm Burp MCP reachable.
2. Require `out/<slug>/webvuln/surface/*.json` (run `/webvuln-surface` first). Auth-context at `/mnt/files/bb-agent/<slug>/webvuln/auth/context.json` is optional.
3. Apply the **offensive-request-smuggling** skill methodology under the compliance gate.
4. Read the structured payload bank (`_resources/payloads/smuggling.json`). First fingerprint architecture per host (CDN/proxy/load-balancer headers, HTTP/2 support), then test ranked hosts by tier (tier1: CDN+proxy+H2 → tier4: single server), iterating probes systematically by phase:
   - **Phase 0 detection** (timing probes: CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, CL.0, h2c — measure delay on follow-up request) → **Phase 1 confirmation** (GPOST method confusion and path differential on your OWN follow-up; 3× repetition for reliability) → **Phase 2 self-poisoning** (response queue poisoning on own connection for bug_bounty; + test-path cache poisoning and self-XSS for contracted_pentest) → **Phase 3 TE obfuscation** (16 header variants when standard probes fail) → **Phase 4 H2 specific** (CRLF injection, duplicate CL, :method override, :path injection, :authority/Host conflict, h2c upgrade, CONTINUATION splitting).
   Apply suspicion scoring (0–100) with engagement-type-aware thresholds. **All probes affect ONLY your own connection.**
   **Proof ceiling: timing + differential proof on own requests (bug_bounty) or + self-impact demonstration (contracted_pentest) — then STOP.** No poisoning other users, no DoS, no cache poisoning on production paths, no credential theft, no restricted resource access. Honor `rate_limit_cap_rps` (default 2 r/s). Track every probe id as tested/hit/blocked/skipped.
5. Write `out/<slug>/webvuln/smuggling/<UTC-ts>.json` (redacted; raw evidence 0700 under `/mnt/files`).

When the subagent returns, relay:
- the funnel: `hosts → architecture_fingerprinted → timing_tested → confirmed by variant (cl_te / te_cl / te_te / h2_cl / h2_te / cl_0 / h2c)` + enforced-negative count + waf_detected count,
- architecture summary (CDN/proxy types identified, HTTP/2 support distribution),
- `unauth_only` status,
- top confirmed findings as `variant @ host (severity=, confidence=)` with one-line proof,
- the literal next steps per confirmed host: `/verify-ownership <slug> <host>`, then `/draft-report <slug> <host-or-asset>`.

Reminder to the user: **proof ceiling respected — desync demonstrated on own requests only. No other-user impact, no DoS, no production cache poisoning.** report-drafter caps severity to `scope.severity_cap`; **no auto-submit** — human reviews, pastes, then `/outcome` closes the loop.
