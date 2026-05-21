---
description: Scout publicly-listed HackerOne, Bugcrowd, or Intigriti bug-bounty programs likely to yield passive-recon findings (leaked creds, exposed buckets, takeover). Reads no program assets.
argument-hint: [platform] [top_n] [key=value...]
allowed-tools: Agent
---

You are kicking off program scouting for bb-agent.

Arguments: $ARGUMENTS  (all optional)

## Parsing $ARGUMENTS

Be a lenient parser. Accept any of these forms and build the filter JSON for `program-scout`:

| Input form | Example | Build |
|---|---|---|
| empty | `` | `{}` |
| bare platform | `intigriti` | `{"platform":"intigriti"}` |
| platform + bare int (`top_n`) | `intigriti 5` | `{"platform":"intigriti","top_n":5}` |
| platform + key=value pairs | `intigriti top_n=5 min_max_payout=10000` | `{"platform":"intigriti","top_n":5,"min_max_payout":10000}` |
| disable company dedup | `intigriti company_dedup=false` | `{"platform":"intigriti","company_dedup":false}` |
| key=value pairs only | `top_n=5 require_wildcard=true` | `{"top_n":5,"require_wildcard":true}` (platform defaults to hackerone) |
| JSON | `{"platform":"bugcrowd","top_n":5}` | passed through verbatim |
| natural language | `from intigriti top 5` | extract platform + top_n; build JSON |

Rules:
- Platform tokens accepted: `hackerone` / `h1`, `bugcrowd` / `bc`, `intigriti` / `int`. Aliases get normalized to the canonical form. Anything else as token-1 → treat as a key=value parse failure, fall through to natural-language extraction.
- A bare positional integer after the platform is interpreted as `top_n`.
- Booleans: `true` / `false` (case-insensitive). Integers: anything matching `^-?\d+$`. Strings: everything else.
- Unknown keys → forward to program-scout anyway; the agent rejects what it doesn't understand.

If the input is ambiguous (e.g. two platform tokens, two `top_n` values), pick the first occurrence and note the ambiguity in your reply to the user.

Delegate to the `program-scout` subagent. Pass the **built JSON object** as the input. Require it to:

1. Parse filters; apply defaults (`platform="hackerone"`, `min_critical_eligible=1`, `min_max_payout=1`, `min_tier1_count=0`, `top_n=10`, `require_wildcard=false`, `min_in_scope=0`, `exclude_slugs=[]`). Reject `top_n > 25`. Reject `platform` not in `{"hackerone", "bugcrowd", "intigriti"}`. Note: retired filters `min_critical_bounty`, `require_safe_harbor`, `require_no_scanner_ban` are no longer accepted. Platform-specific filters: `min_critical_eligible` applies to H1 only; `min_max_payout` applies to Bugcrowd and Intigriti (normalized to USD for Intigriti); `min_tier1_count` applies to Intigriti only.
2. Fetch the matching dump exactly once:
   - `platform=hackerone` → `https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json`
   - `platform=bugcrowd` → `https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json`
   - `platform=intigriti` → `https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json`
   No per-program HTTP calls; no probing program assets.
3. Auto-exclude slugs already in `memory/programs/*.json` **whose stored `program.platform` matches the scout target**, plus any in `exclude_slugs` from the input. Slug prefixes: H1 unprefixed, BC uses `bc-`, Intigriti uses `int-`. (Cross-platform name collisions are kept separate.)
4. Pre-filter:
   - H1: open + bounty-offering programs with at least `min_critical_eligible` bounty-eligible critical-severity assets.
   - Bugcrowd: programs with `max_payout >= min_max_payout` (Bugcrowd dump lists only active engagements; no `submission_state` field).
   - Intigriti: `status=="open"` AND `confidentiality_level=="public"` AND `max_payout_usd >= min_max_payout` (EUR×1.07, GBP×1.28 normalization) AND `tier1_count >= min_tier1_count`.
5. Score using platform-specific rubric:
   - H1: `has_source_code (+4)`, `has_wildcard (+2)`, url-domain tiers (≥10/≥30), in-scope tiers (≥50/≥200). Max score 10.
   - Bugcrowd: `has_wildcard (+2)`, url-domain tiers, in-scope tiers, `max_payout` tiers (≥5K/≥10K). Max score 7. **No `has_source_code` signal — Bugcrowd dump doesn't expose it.**
   - Intigriti: `has_tier1 (+3)`, `has_wildcard (+2)`, url-domain tiers (≥10/≥30), in-scope tiers (≥50/≥200), `max_payout_usd` tiers (≥5K/≥10K). Max score 11. **No `has_source_code` signal — Intigriti dump doesn't expose it.**
6. Write top N to `/home/kenny/bb-agent/out/scout/<UTC-ts>.json` in the documented schema.

When the subagent returns, give the user a tight summary:
- output file path
- platform scouted
- counts: directory_total / pre_filtered / scored / returned
- top 3 candidates as `rank. slug @ score — top-signal-or-two`
- exact next commands per pick: `/program-load <url>` then `/hunt-secrets <slug>` and `/hunt-buckets <slug>`
- if Bugcrowd or Intigriti: surface the SOURCE_CODE caveat (scout can't see declared repos; pair with manual GitHub search of the company name)

Reminder: program-scout does NOT ingest anything itself, does NOT touch any program-owned asset, and makes exactly one outbound HTTP call (the dump fetch). The human picks winners and invokes `/program-load`. Scores are intra-platform — don't compare scores across H1 (max 10), Intigriti (max 11), and Bugcrowd (max 7).
