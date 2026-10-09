---
description: Active OS command injection hunt for an ingested program. Runs nuclei RCE/cmdi templates as fast bulk pre-filter, then confirms/extends via Burp with time-delay detection, OOB Collaborator callbacks, inline output probes, context-escape payloads, and filter bypass. Confirms to the proof ceiling (single innocuous command output id/hostname for bug_bounty; same + OS/context for contracted_pentest — never destructive commands, never reverse shells). Writes redacted candidates; does not verify ownership or draft.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off active OS command injection hunting for program slug: $ARGUMENTS

Delegate to the `rce-hunter` subagent. Require it to:
1. Read `.claude/skills/webvuln-compliance/SKILL.md` + `memory/programs/<slug>.json`; apply the §1 hard gate (**REFUSE** + empty-candidates output with `refused_reason` on `automated_tools_allowed==false` / `explicit_scanner_ban==true` / out-of-scope). Confirm Burp MCP + Collaborator reachable.
2. Require `out/<slug>/webvuln/surface/*.json` (run `/webvuln-surface` first). Auth-context at `/mnt/files/bb-agent/<slug>/webvuln/auth/context.json` is optional — without it, only unauthenticated endpoints are tested (note `unauth_only=true`).
3. Apply the **offensive-rce** skill methodology (command injection section) under the compliance gate. This hunter covers OS command injection ONLY — not SSTI, deserialization, or file upload RCE.
4. Read the structured payload bank (`_resources/payloads/rce.json`). Test injection points ranked by tier (tier1: high-value param name + diagnostic endpoint + auth → tier5: unranked), iterating payloads systematically by phase:
   - **Phase N nuclei bulk pre-filter** (`-tags rce,cmdi,command-injection`, routed through Burp proxy, `-rl 2`) → Phase 0 time-delay detection (sleep/ping canaries; skipped for nuclei-confirmed) → Phase 1 OOB Collaborator callbacks (curl/wget/nslookup; poll at 10s/30s/60s) → Phase 2 inline output probes (`;id`, `|id`, `$(id)` — primary proof) → Phase 3 context escape (quote break, newline, IP/filename suffix) → Phase 4 filter bypass (space bypass ${IFS}/brace, keyword bypass quote-break/base64/wildcard, char bypass newline/%0a) → Phase 5 OS confirmation (contracted_pentest only; `uname -a`/`ver`/`pwd`).
   nuclei confirmed findings get fast-path score boost (+35). Apply suspicion scoring (0–100, Phase N scores included) with engagement-type-aware thresholds.
   **Proof ceiling: single innocuous command output (id/hostname) — then STOP.** No destructive commands, no file reads (/etc/shadow, /etc/passwd, .env), no reverse shells, no persistence, no pivoting, no data exfiltration beyond proof. Honor `rate_limit_cap_rps` (default 2 r/s). Track every payload id as tested/hit/blocked/skipped.
5. Write `out/<slug>/webvuln/rce/<UTC-ts>.json` (redacted; raw evidence 0700 under `/mnt/files`).

When the subagent returns, relay:
- the funnel: `seeds → nuclei-prescan → candidates_tested → confirmed by type (inline / time / oob / error_leak)` + nuclei prescan stats (confirmed/partial) + enforced-negative count + filter_blocked count,
- `unauth_only` status,
- OS detected across confirmed findings,
- top confirmed findings as `type @ url:param (severity=, confidence=)` with one-line redacted proof,
- the literal next steps per confirmed host: `/verify-ownership <slug> <host>`, then `/draft-report <slug> <host-or-asset>`.

Reminder to the user: **proof ceiling respected — single innocuous command output (id/hostname). No destructive commands, no file reads, no reverse shells, no persistence.** report-drafter caps severity to `scope.severity_cap`; **no auto-submit** — human reviews, pastes, then `/outcome` closes the loop.
