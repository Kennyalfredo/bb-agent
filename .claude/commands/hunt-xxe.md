---
description: Active XXE hunt for an ingested program. Runs nuclei XXE templates as fast bulk pre-filter, then confirms/extends via Burp with entity detection, OOB Collaborator exfiltration, innocuous file read, SSRF reachability (pentest only), blind XXE, and filter bypass. Confirms to the proof ceiling (OOB callback OR single /etc/hostname-class file read — never /etc/shadow, never large files, never internal port scanning, never billion-laughs DoS). Writes redacted candidates; does not verify ownership or draft.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off active XXE hunting for program slug: $ARGUMENTS

Delegate to the `xxe-hunter` subagent. Require it to:
1. Read `.claude/skills/webvuln-compliance/SKILL.md` + `memory/programs/<slug>.json`; apply the §1 hard gate (**REFUSE** + empty-candidates output with `refused_reason` on `automated_tools_allowed==false` / `explicit_scanner_ban==true` / out-of-scope). Confirm Burp MCP + Collaborator reachable.
2. Require `out/<slug>/webvuln/surface/*.json` (run `/webvuln-surface` first). Auth-context at `/mnt/files/bb-agent/<slug>/webvuln/auth/context.json` is optional — without it, only unauthenticated endpoints are tested (note `unauth_only=true`).
3. Apply the **offensive-xxe** skill methodology under the compliance gate.
4. Read the structured payload bank (`_resources/payloads/xxe.json`). Test injection points ranked by tier (tier1: XML/SOAP content-type+auth → tier6: remaining body endpoints), iterating payloads systematically by phase:
   - **Phase N nuclei XXE templates bulk pre-filter** (detection templates only, routed through Burp proxy) → Phase 0 entity detection (internal entity expansion, external DTD fetch, parameter entities; skipped for nuclei-confirmed) → Phase 1 OOB exfiltration (Collaborator HTTP/DNS callbacks — primary detection; poll at 10s/30s/60s) → Phase 2 file read (/etc/hostname class ONLY — **bug_bounty ceiling**) → Phase 3 SSRF probe (contracted_pentest only; cloud metadata reachability, localhost — NEVER extract credentials) → Phase 4 blind XXE (error-based, local DTD repurpose — when OOB and direct both fail) → Phase 5 filter bypass (encoding, XInclude, SVG/DOCX/XLSX wrappers, protocol alternatives).
   Nuclei confirmed findings get fast-path score boost (+35). Apply suspicion scoring (0–100, Phase N scores included) with engagement-type-aware thresholds.
   **Proof ceiling: OOB callback OR /etc/hostname-class file read — then STOP.** No /etc/shadow, no large file reads, no cloud credential extraction (stop at reachability), no internal port scanning, no billion-laughs DoS. Honor `rate_limit_cap_rps` (default 2 r/s). Track every payload id as tested/hit/blocked/skipped.
5. Write `out/<slug>/webvuln/xxe/<UTC-ts>.json` (redacted; raw evidence 0700 under `/mnt/files`).

When the subagent returns, relay:
- the funnel: `seeds → nuclei-prescan → candidates_tested → confirmed by type (classic / oob / file_read / blind / ssrf)` + nuclei prescan stats (confirmed/partial) + enforced-negative count + filter_blocked count,
- `unauth_only` status,
- Collaborator interaction summary (total, HTTP vs DNS-only),
- parsers identified (libxml2, SAX, etc.),
- content-type switch results (JSON→XML accepted count),
- top confirmed findings as `type @ url (severity=, confidence=)` with one-line redacted proof,
- the literal next steps per confirmed host: `/verify-ownership <slug> <host>`, then `/draft-report <slug> <host-or-asset>`.

Reminder to the user: **proof ceiling respected — OOB callback + /etc/hostname-class file read only. No /etc/shadow, no large file reads, no credential extraction, no internal port scanning, no billion-laughs DoS.** report-drafter caps severity to `scope.severity_cap`; **no auto-submit** — human reviews, pastes, then `/outcome` closes the loop.
