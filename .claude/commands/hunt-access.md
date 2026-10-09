---
description: Active IDOR / BOLA / BFLA / mass-assignment hunt for an ingested program. Consumes the webvuln-surface seeds + a two-account auth-context, replays object-reference requests cross-account via Burp, and confirms broken access control to the proof ceiling (read ONE adjacent object — never enumerate). Writes redacted candidates; does not verify ownership or draft.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off active access-control hunting for program slug: $ARGUMENTS

Delegate to the `access-control-hunter` subagent. Require it to:
1. Read `.claude/skills/webvuln-compliance/SKILL.md` + `memory/programs/<slug>.json`; apply the §1 hard gate (**REFUSE** + empty-candidates output with `refused_reason` on `automated_tools_allowed==false` / `explicit_scanner_ban==true` / out-of-scope). Confirm Burp MCP is reachable.
2. Require `out/<slug>/webvuln/surface/*.json` (run `/webvuln-surface` first) and `/mnt/files/bb-agent/<slug>/webvuln/auth/context.json` (run `/auth-load` first). Two validated accounts → full cross-account IDOR/BOLA; one → degraded BFLA/forced-browsing only (note it).
3. Apply the **offensive-idor** skill methodology under the compliance gate.
4. Test object-ref endpoints cross-account, BFLA forced-browsing, and read-only mass-assignment (on account_a's own object only). **Proof ceiling: read ONE adjacent object / reach ONE privileged function — then STOP.** No range enumeration, no privileged-action invocation, no victim-data harvesting. One variation per denied candidate (encoded id / method swap / array-wrap / param pollution / `.json`), stopping at first confirmation. Honor `rate_limit_cap_rps` (default 2 r/s).
5. Write `out/<slug>/webvuln/access/<UTC-ts>.json` (redacted; raw evidence 0700 under `/mnt/files`).

When the subagent returns, relay:
- the funnel: `seeds → candidates_tested → confirmed by class (idor / bola / bfla / mass_assignment)` + enforced-negative count,
- `degraded_mode` status (true = only one account, partial coverage),
- top confirmed findings as `class @ url (severity=, confidence=)` with the one-line redacted proof,
- the literal next steps per confirmed host: `/verify-ownership <slug> <host>` (the `in_scope_subdomain_override` auto-fires for in-scope wildcards), then `/draft-report <slug> <host-or-asset>`.

Reminder to the user: **proof ceiling respected — one object read, no enumeration, no privileged action invoked.** report-drafter caps severity to `scope.severity_cap`; **no auto-submit** — human reviews, pastes, then `/outcome` closes the loop.
