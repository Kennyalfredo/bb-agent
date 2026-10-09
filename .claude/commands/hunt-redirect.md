---
description: Active open-redirect hunt for an ingested program. Runs nuclei redirect templates as fast bulk pre-filter, then confirms/extends via Burp with parameter discovery, basic redirect probes, filter bypass (encoding, domain spoofing, protocol confusion), path-based redirects, and header-based redirects. Confirms to the proof ceiling (redirect to Collaborator domain for bug_bounty; extends to chaining demo for contracted_pentest — never actual phishing, never token theft from other users). Writes redacted candidates; does not verify ownership or draft.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off active open-redirect hunting for program slug: $ARGUMENTS

Delegate to the `redirect-hunter` subagent. Require it to:
1. Read `.claude/skills/webvuln-compliance/SKILL.md` + `memory/programs/<slug>.json`; apply the §1 hard gate (**REFUSE** + empty-candidates output with `refused_reason` on `automated_tools_allowed==false` / `explicit_scanner_ban==true` / out-of-scope). Confirm Burp MCP + Collaborator reachable.
2. Require `out/<slug>/webvuln/surface/*.json` (run `/webvuln-surface` first). Auth-context at `/mnt/files/bb-agent/<slug>/webvuln/auth/context.json` is optional — without it, only unauthenticated endpoints are tested (note `unauth_only=true`).
3. Apply the **offensive-open-redirect** skill methodology under the compliance gate.
4. Read the structured payload bank (`_resources/payloads/open-redirect.json`). Test injection points ranked by tier (tier1: redirect_uri+OAuth+auth → tier5: unranked), iterating payloads systematically by phase:
   - **Phase N nuclei bulk pre-filter** (`-tags redirect`, routed through Burp proxy, `-fr` follow redirects) → Phase 0 parameter discovery (same-origin redirect probes to identify redirect-driving params) → Phase 1 basic redirect (direct external redirect to Collaborator; **bug_bounty ceiling** if any succeeds) → Phase 2 filter bypass (domain spoofing, encoding, protocol confusion, special chars — one payload per sub-category) → Phase 3 path-based redirect (path traversal/segment techniques) → Phase 4 header redirect (Host, X-Forwarded-Host, Referer injection).
   Nuclei confirmed findings get fast-path score boost (+35). Apply suspicion scoring (0–100, Phase N scores included) with engagement-type-aware thresholds.
   **Proof ceiling: redirect to Collaborator domain (bug_bounty) or redirect + chaining demonstration (contracted_pentest) — then STOP.** No phishing pages, no token theft from other users, no credential harvesting, no social engineering. Honor `rate_limit_cap_rps` (default 2 r/s). Track every payload id as tested/hit/blocked/skipped.
5. Write `out/<slug>/webvuln/redirect/<UTC-ts>.json` (redacted; raw evidence 0700 under `/mnt/files`).

When the subagent returns, relay:
- the funnel: `seeds → nuclei-prescan → candidates_tested → confirmed by type (3xx / meta / js / header / ssrf)` + nuclei prescan stats (confirmed/informational) + enforced-negative count + filter_blocked count,
- `unauth_only` status,
- redirect types found (3xx, meta, JS, header, server-side follow),
- bypass techniques that succeeded,
- auth-flow redirects (login/OAuth endpoints),
- top confirmed findings as `type @ url:param (severity=, confidence=)` with one-line redacted proof,
- the literal next steps per confirmed host: `/verify-ownership <slug> <host>`, then `/draft-report <slug> <host-or-asset>`.

Reminder to the user: **proof ceiling respected — redirect to Collaborator only. No phishing, no token theft from other users, no credential harvesting.** report-drafter caps severity to `scope.severity_cap`; **no auto-submit** — human reviews, pastes, then `/outcome` closes the loop.
