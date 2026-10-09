---
description: Active SSTI hunt for an ingested program. Runs Tplmap as fast bulk pre-filter, then confirms/extends via Burp with polyglot canaries, engine identification, eval confirmation, info leak, and filter bypass payloads. Confirms to the proof ceiling (arithmetic eval + engine ID for bug_bounty; single id/hostname exec for contracted_pentest — never destructive commands, never sensitive file reads). Writes redacted candidates; does not verify ownership or draft.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off active SSTI hunting for program slug: $ARGUMENTS

Delegate to the `ssti-hunter` subagent. Require it to:
1. Read `.claude/skills/webvuln-compliance/SKILL.md` + `memory/programs/<slug>.json`; apply the §1 hard gate (**REFUSE** + empty-candidates output with `refused_reason` on `automated_tools_allowed==false` / `explicit_scanner_ban==true` / out-of-scope). Confirm Burp MCP reachable.
2. Require `out/<slug>/webvuln/surface/*.json` (run `/webvuln-surface` first). Auth-context at `/mnt/files/bb-agent/<slug>/webvuln/auth/context.json` is optional — without it, only unauthenticated endpoints are tested (note `unauth_only=true`).
3. Apply the **offensive-ssti** skill methodology under the compliance gate.
4. Read the structured payload bank (`_resources/payloads/ssti.json`). Test injection points ranked by tier (tier1: auth+template-rendering-endpoint → tier5: unranked), iterating payloads systematically by phase:
   - **Phase T Tplmap bulk pre-filter** (`--level 1`, `-t RT`, routed through Burp proxy, NEVER `--os-cmd`/`--os-shell`) → Phase 0 polyglot canary (mathematical eval detection; skipped for Tplmap-confirmed) → Phase 1 engine identification (PortSwigger decision tree) → Phase 2 eval confirmation (engine-specific arithmetic; **bug_bounty ceiling**) → Phase 3 info leak (contracted_pentest only; config/env access) → Phase 4 RCE proof (contracted_pentest only; single `id`/`hostname` exec then STOP) → Phase 5 filter bypass (one round of encoding/attr()/bracket/concat bypasses) → Phase 6 Tplmap deep confirmation (only manually-discovered candidates not confirmed by Phase T).
   Tplmap confirmed findings get fast-path score boost (+35). Apply suspicion scoring (0–100, Phase T scores included) with engagement-type-aware thresholds.
   **Proof ceiling: arithmetic eval + engine ID (bug_bounty) or single innocuous command exec (contracted_pentest) — then STOP.** No destructive commands, no sensitive file reads (/etc/shadow, .env, private keys), no reverse shells, no pivoting, no data exfiltration, no DoS via template recursion. Honor `rate_limit_cap_rps` (default 2 r/s). Track every payload id as tested/hit/blocked/skipped.
5. Write `out/<slug>/webvuln/ssti/<UTC-ts>.json` (redacted; raw evidence 0700 under `/mnt/files`).

When the subagent returns, relay:
- the funnel: `seeds → tplmap-prescan → candidates_tested → confirmed by type (eval / rce / info_leak / sandboxed)` + Tplmap prescan stats (confirmed/partial) + enforced-negative count + filter_blocked count,
- `unauth_only` status,
- engines identified across all confirmed findings,
- top confirmed findings as `engine @ url:param (severity=, confidence=)` with one-line redacted proof,
- the literal next steps per confirmed host: `/verify-ownership <slug> <host>`, then `/draft-report <slug> <host-or-asset>`.

Reminder to the user: **proof ceiling respected — arithmetic eval + engine ID (bug_bounty) or single `id`/`hostname` exec (contracted_pentest). No destructive commands, no sensitive file reads, no reverse shells.** report-drafter caps severity to `scope.severity_cap`; **no auto-submit** — human reviews, pastes, then `/outcome` closes the loop.
