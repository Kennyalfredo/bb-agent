---
description: Active SSRF hunt for an ingested program. Runs SSRFmap as fast bulk pre-filter (safe modules only), then confirms/extends via Burp using OOB callbacks (Collaborator), localhost probes, cloud metadata reachability, protocol handlers, and IP bypass techniques. Confirms to the proof ceiling (OOB callback or reachability proof — never extract cloud credentials, never pivot to internal services). Writes redacted candidates; does not verify ownership or draft.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off active SSRF hunting for program slug: $ARGUMENTS

Delegate to the `ssrf-hunter` subagent. Require it to:
1. Read `.claude/skills/webvuln-compliance/SKILL.md` + `memory/programs/<slug>.json`; apply the §1 hard gate (**REFUSE** + empty-candidates output with `refused_reason` on `automated_tools_allowed==false` / `explicit_scanner_ban==true` / out-of-scope). Confirm Burp MCP + Collaborator reachable.
2. Require `out/<slug>/webvuln/surface/*.json` (run `/webvuln-surface` first). Auth-context at `/mnt/files/bb-agent/<slug>/webvuln/auth/context.json` is optional — without it, only unauthenticated endpoints are tested (note `unauth_only=true`).
3. Apply the **offensive-ssrf** skill methodology under the compliance gate.
4. Read the structured payload bank (`_resources/payloads/ssrf.json`). Test injection points ranked by tier (tier1: auth+fetcher_endpoint → tier5: unranked), iterating payloads systematically by phase:
   - **Phase SM SSRFmap bulk pre-filter** (safe modules only: readfiles /etc/hostname + aws/gce/digitalocean metadata, `--level 1`, routed through Burp proxy) → Phase 0 OOB canary (Collaborator callback — primary detection; skipped for SSRFmap-confirmed) → Phase 1 localhost probes (response-based) → Phase 2 cloud metadata reachability (skipped for SSRFmap-confirmed) → Phase 3 protocol handlers (file:///etc/hostname — contracted_pentest only; skipped for SSRFmap-confirmed) → Phase 4 IP bypass (decimal/hex/octal/IPv6 — when direct probes blocked) → Phase 5 filter bypass (URL tricks, encoding, redirect chains) → Phase 6 blind timing (port response-time delta — contracted_pentest only).
   SSRFmap confirmed findings get fast-path score boost (+35). Poll Collaborator at intervals (10s, 30s, 60s) after each OOB batch. Apply suspicion scoring (0–100, Phase SM scores included) with engagement-type-aware thresholds.
   **Proof ceiling: OOB callback or reachability proof — then STOP.** No cloud credential extraction (stop at 169.254.169.254 reachability), no internal service pivoting, no sensitive file reads, no SSRF→RCE chains. Honor `rate_limit_cap_rps` (default 2 r/s). Track every payload id as tested/hit/blocked/skipped.
5. Write `out/<slug>/webvuln/ssrf/<UTC-ts>.json` (redacted; raw evidence 0700 under `/mnt/files`).

When the subagent returns, relay:
- the funnel: `seeds → ssrfmap-prescan → candidates_tested → confirmed by type (oob / response / cloud_meta / protocol / timing)` + SSRFmap prescan stats (confirmed/anomaly) + enforced-negative count + filter_blocked count,
- `unauth_only` status,
- Collaborator callback summary (total received, HTTP vs DNS-only),
- cloud metadata reachability findings,
- top confirmed findings as `type @ url:param (severity=, confidence=)` with one-line redacted proof,
- the literal next steps per confirmed host: `/verify-ownership <slug> <host>`, then `/draft-report <slug> <host-or-asset>`.

Reminder to the user: **proof ceiling respected — OOB callback / reachability proof only. No credential extraction, no internal service pivoting, no sensitive file reads.** report-drafter caps severity to `scope.severity_cap`; **no auto-submit** — human reviews, pastes, then `/outcome` closes the loop.
