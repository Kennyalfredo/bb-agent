---
description: Active file upload vulnerability hunt for an ingested program. Tests extension bypass, Content-Type manipulation, magic byte forging, polyglot files, path traversal in filenames, and storage/access behavior via Burp MCP. Confirms to the proof ceiling (restricted-type accepted AND accessible for bug_bounty; benign execution proof for contracted_pentest — never actual webshells, malware, or file overwrite). Writes redacted candidates; does not verify ownership or draft.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off active file upload vulnerability hunting for program slug: $ARGUMENTS

Delegate to the `upload-hunter` subagent. Require it to:
1. Read `.claude/skills/webvuln-compliance/SKILL.md` + `memory/programs/<slug>.json`; apply the §1 hard gate (**REFUSE** + empty-candidates output with `refused_reason` on `automated_tools_allowed==false` / `explicit_scanner_ban==true` / out-of-scope). Confirm Burp MCP reachable.
2. Require `out/<slug>/webvuln/surface/*.json` (run `/webvuln-surface` first). Auth-context at `/mnt/files/bb-agent/<slug>/webvuln/auth/context.json` is optional — without it, only unauthenticated upload endpoints are tested (note `unauth_only=true`).
3. Apply the **offensive-file-upload** skill methodology under the compliance gate.
4. Read the structured payload bank (`_resources/payloads/upload.json`). Test upload endpoints ranked by tier (tier1: avatar/profile same-origin → tier5: remaining multipart), iterating payloads systematically by phase:
   - Phase 0 discovery (baseline uploads, client/server validation detection, storage analysis) → Phase 1 extension bypass (direct restricted, double extension, alternate, case variation, null byte, special chars, .htaccess) → Phase 2 Content-Type bypass (MIME mismatch, remove/double Content-Type) → Phase 3 magic bytes/polyglot (GIF89a/PNG/JPEG prefix + restricted body, EXIF injection) → Phase 4 path traversal (filename directory escape, encoded traversal) → Phase 5 storage probe (access URL, Content-Type served, nosniff, same-origin, execution, directory listing, access control).
   Apply suspicion scoring (0–100) with engagement-type-aware thresholds.
   **Proof ceiling: restricted type accepted + accessible (bug_bounty) or benign execution proof (contracted_pentest) — then STOP.** No webshells, no malware, no file overwrite. All proof files use `bb-agent-proof-` prefix. Honor `rate_limit_cap_rps` (default 2 r/s). Track every payload id as tested/hit/blocked/skipped.
5. Write `out/<slug>/webvuln/upload/<UTC-ts>.json` (redacted; raw evidence 0700 under `/mnt/files`).

When the subagent returns, relay:
- the funnel: `upload_endpoints_found → endpoints_tested → bypass_confirmed by type (extension / content_type / magic / path / execution)` + enforced-negative count,
- `unauth_only` status,
- storage analysis (same-origin vs CDN/S3, filename handling),
- server technology detected,
- top confirmed findings as `bypass_type @ url (severity=, confidence=)` with one-line redacted proof,
- the literal next steps per confirmed host: `/verify-ownership <slug> <host>`, then `/draft-report <slug> <host-or-asset>`.

Reminder to the user: **proof ceiling respected — restricted type accepted + accessible (bug_bounty) or benign execution proof (contracted_pentest). No webshells, no malware, no file overwrite. All proof files use bb-agent-proof- prefix for cleanup.** report-drafter caps severity to `scope.severity_cap`; **no auto-submit** — human reviews, pastes, then `/outcome` closes the loop.
