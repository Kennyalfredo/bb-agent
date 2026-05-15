---
description: Scout publicly-listed HackerOne bug-bounty programs likely to yield passive-recon findings (leaked creds, exposed buckets, takeover). Reads no program assets.
argument-hint: [optional-filters-json]
allowed-tools: Agent
---

You are kicking off program scouting for bb-agent.

Arguments: $ARGUMENTS  (optional — may be empty, or a JSON filters object like `{"min_critical_eligible": 20, "require_wildcard": true, "top_n": 5}`)

Delegate to the `program-scout` subagent. Pass the arguments verbatim (or `{}` if empty). Require it to:

1. Parse filters; apply defaults (`min_critical_eligible=1`, `top_n=10`, `require_wildcard=false`, `min_in_scope=0`, `exclude_slugs=[]`). Reject `top_n > 25`. Note: retired filters `min_critical_bounty`, `require_safe_harbor`, `require_no_scanner_ban` are no longer accepted — the dump doesn't include policy text or bounty $ amounts.
2. Fetch the H1 dump exactly once from `https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json`. No per-program HTTP calls; no probing program assets.
3. Auto-exclude slugs already in `memory/programs/*.json` plus any in `exclude_slugs` from the input.
4. Pre-filter to open + bounty-offering programs with at least `min_critical_eligible` bounty-eligible critical-severity assets.
5. Score each by signals from the dump alone: critical-eligible volume tiers (≥1/≥5/≥20/≥50), wildcard presence, in-scope-size tiers, asset diversity (mobile / source code), critical-ratio quality.
6. Write top N to `/home/kenny/bb-agent/out/scout/<UTC-ts>.json` in the documented schema.

When the subagent returns, give the user a tight summary:
- output file path
- counts: directory_total / pre_filtered / scored / returned
- top 3 candidates as `rank. slug @ score — top-signal-or-two`
- exact next commands per pick: `/program-load <url>` then `/hunt-secrets <slug>` and `/hunt-buckets <slug>`

Reminder: program-scout does NOT ingest anything itself, does NOT touch any program-owned asset, and makes exactly one outbound HTTP call (the dump fetch). The human picks winners and invokes `/program-load`.
