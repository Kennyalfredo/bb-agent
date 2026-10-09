---
description: Active insecure deserialization hunt for an ingested program. Tests Java (ObjectInputStream, XStream, Jackson, Fastjson), PHP (unserialize, PHAR), .NET (BinaryFormatter, Json.NET, ViewState), Python (pickle, PyYAML), Ruby (Marshal, YAML), and Node.js (node-serialize) deserialization sinks via Burp MCP. Confirms to the proof ceiling (DNS/HTTP callback via safe gadget for bug_bounty; single id/hostname exec for contracted_pentest — never destructive payloads, never file writes, never reverse shells). Writes redacted candidates; does not verify ownership or draft.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off active deserialization hunting for program slug: $ARGUMENTS

Delegate to the `deser-hunter` subagent. Require it to:
1. Read `.claude/skills/webvuln-compliance/SKILL.md` + `memory/programs/<slug>.json`; apply the §1 hard gate (**REFUSE** + empty-candidates output with `refused_reason` on `automated_tools_allowed==false` / `explicit_scanner_ban==true` / out-of-scope). Confirm Burp MCP + Collaborator reachable.
2. Require `out/<slug>/webvuln/surface/*.json` (run `/webvuln-surface` first). Auth-context at `/mnt/files/bb-agent/<slug>/webvuln/auth/context.json` is optional — without it, only unauthenticated endpoints are tested (note `unauth_only=true`).
3. Apply the **offensive-deserialization** skill methodology under the compliance gate.
4. Read the structured payload bank (`_resources/payloads/deser.json`). Test candidates ranked by tier (tier1: serialized session cookie → tier6: framework errors), iterating payloads systematically by phase:
   - Phase 0 detection (magic bytes, content-types, base64 blobs) → Phase 1 fingerprint (corrupt payload → error messages revealing framework) → Phase 2 gadget probe (safe DNS/HTTP callbacks via URLDNS/InetAddress/Guzzle — PRIMARY bug_bounty confirmation) → Phase 3 OOB confirmation (labeled gadget-specific Collaborator callbacks) → Phase 4 RCE proof (contracted_pentest only; single `id`/`hostname` then STOP) → Phase 5 filter bypass (encoding, alternative gadgets, content-type switching, PHAR wrapper).
   Apply suspicion scoring (0–100) with engagement-type-aware thresholds. Poll Collaborator at intervals (10s, 30s, 60s) after each gadget batch.
   **Proof ceiling: DNS/HTTP callback via safe gadget (bug_bounty) or single innocuous command exec (contracted_pentest) — then STOP.** No destructive commands, no file writes, no reverse shells, no persistence, no DoS via resource exhaustion. Honor `rate_limit_cap_rps` (default 2 r/s). Track every payload id as tested/hit/blocked/skipped.
5. Write `out/<slug>/webvuln/deser/<UTC-ts>.json` (redacted; raw evidence 0700 under `/mnt/files`).

When the subagent returns, relay:
- the funnel: `seeds → serialized_data_detected → fingerprinted → callback_confirmed → rce_confirmed` + enforced-negative count + filter_blocked count,
- `unauth_only` status,
- Collaborator interaction summary (DNS vs HTTP, labeled subdomains),
- languages and frameworks identified,
- confirmed gadget chains,
- top confirmed findings as `language:framework @ url:param (severity=, confidence=)` with one-line redacted proof,
- the literal next steps per confirmed host: `/verify-ownership <slug> <host>`, then `/draft-report <slug> <host-or-asset>`.

Reminder to the user: **proof ceiling respected — DNS/HTTP callback via safe gadget (bug_bounty) or single `id`/`hostname` exec (contracted_pentest). No destructive commands, no file writes, no reverse shells.** report-drafter caps severity to `scope.severity_cap`; **no auto-submit** — human reviews, pastes, then `/outcome` closes the loop.
