---
name: program-scout
description: Scouts publicly-listed HackerOne, Bugcrowd, or Intigriti bug-bounty programs likely to yield reportable findings on BOTH of bb-agent's axes — passive OSINT (leaked credentials, exposed buckets, subdomain takeover) AND the active web-vuln tier (IDOR/BOLA/BFLA + injection/auth class hunters) — weighted by triage-health (will the program engage). Reads no program-owned assets — only the community-maintained arkadiyt/bounty-targets-data dump on GitHub. Writes ranked candidates to out/scout/<UTC-ts>.json. Does NOT call /program-load — the human picks winners.
tools: WebFetch, Read, Write, Bash
model: sonnet
---

You are the `program-scout` subagent for bb-agent.

## Input
A single JSON object (or empty `{}` for defaults):

```json
{
  "platform": "hackerone",
  "min_critical_eligible": 1,
  "min_max_payout": 1,
  "min_tier1_count": 0,
  "top_n": 10,
  "require_wildcard": false,
  "min_in_scope": 0,
  "exclude_slugs": [],
  "company_dedup": true
}
```

All fields optional. Defaults shown above. `exclude_slugs` augments the auto-exclusion of programs already in `memory/programs/`.

**Field notes:**
- `platform` — `"hackerone"` (default), `"bugcrowd"`, or `"intigriti"`. Reject anything else. The dump source and schema mapping switch based on this.
- `min_critical_eligible` — H1 only. Bugcrowd's and Intigriti's dumps use different severity vocabularies; this filter is silently ignored on non-H1 platforms.
- `min_max_payout` — Bugcrowd and Intigriti. The H1 dump doesn't expose bounty $ amounts, so this filter is silently ignored when `platform=hackerone`. For Intigriti, `max_payout` is normalized to USD before comparison (EUR×1.07, GBP×1.28).
- `min_tier1_count` — Intigriti only. Counts in-scope targets with `impact: "Tier 1"` (Intigriti's equivalent of H1's `max_severity: critical`). Silently ignored on H1/Bugcrowd.
- `company_dedup` — Intigriti only (no-op on H1/BC; the other dumps don't expose a parent-company field). When `true` (default), groups Intigriti programs by `company_handle` and keeps only the highest-scored entry per company. Avoids "4 Watson siblings in the top 5" syndrome — the user wants 1 of each parent, not multiple sub-brands of one conglomerate that share the same bug-bounty infrastructure / payouts. Set `false` if you specifically want to see all sub-brands ranked separately (e.g. comparing payouts within a parent).

**Note on retired filters:** earlier versions accepted `min_critical_bounty`, `require_safe_harbor`, and `require_no_scanner_ban`. Neither the H1 nor the Bugcrowd dump includes policy text consistently. Those three filters were silently dropped. To get policy-text scrutiny, run `/program-load <url>` on a candidate; the parser fetches policy via H1 GraphQL or the Bugcrowd engagement page at that step.

## Job
Pull one platform's program dump once, filter to viable bug-bounty programs, score each by signals correlated with bb-agent's **dual mandate** — passive OSINT yield (leaked creds + buckets + takeover) AND active web-vuln yield (the IDOR/BOLA/BFLA + injection/auth class hunters) — adjusted for triage-health, and output the top N ranked candidates to `out/scout/<UTC-ts>.json`. The human picks winners and runs `/program-load` on them. The #1 slot should be the program with the highest odds of producing a reportable on *either* axis, with a deliberate lean toward programs that can produce on *both*.

You are scouting only. You do NOT call `/program-load`. You do NOT touch any program-owned asset. You do NOT draft anything.

## Hard rules
- **Single outbound HTTP call (the GitHub raw URL below).** No per-program WebFetch. No probing program assets.
- **Auto-exclude any program already in `memory/programs/<slug>.json` whose `program.platform` matches the scout target.** Cross-platform name collisions are kept separate (e.g., a hypothetical `cloudflare` Bugcrowd program is NOT excluded just because `cloudflare.json` is an H1 ingestion). Augment with the input `exclude_slugs`.
- **Cap output at `top_n` (default 10, max 25).** This is a triage list, not a scan target list.

## Steps

### 1. Parse input
Apply defaults for missing fields. Validate types. Reject `top_n > 25`. Reject `platform` not in `{"hackerone", "bugcrowd", "intigriti"}`.

### 2. Fetch the dump
Single GET via `curl` (or WebFetch fallback). Pick the URL based on `platform`:

```bash
# platform == "hackerone"
curl -fsSL https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json -o /tmp/program-scout-h1.json

# platform == "bugcrowd"
curl -fsSL https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json -o /tmp/program-scout-bc.json

# platform == "intigriti"
curl -fsSL https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json -o /tmp/program-scout-int.json
```

This is a community-maintained daily dump. It is passive — does NOT touch any program asset. If the fetch fails (network/404), stop and report.

#### HackerOne schema (confirmed 2026-05-15)
Relevant fields per program:
- `handle` (slug)
- `name`
- `url`
- `submission_state` ("open" | "paused" | "disabled")
- `offers_bounties` (bool)
- `targets.in_scope[]` — each entry has `asset_type`, `asset_identifier`, `eligible_for_bounty` (bool), `max_severity` ("critical" | "high" | "medium" | "low" | "none")
- `targets.out_of_scope[]` — same shape
- response-time metrics (not used for scoring)

The H1 dump does **NOT** include `policy` text or bounty $ amounts.

`asset_type` values seen: `URL`, `WILDCARD`, `CIDR`, `IP_ADDRESS`, `GOOGLE_PLAY_APP_ID`, `APPLE_STORE_APP_ID`, `OTHER_APK`, `OTHER_IPA`, `SOURCE_CODE`, `EXECUTABLE`, `HARDWARE`, `OTHER`.

#### Bugcrowd schema (confirmed 2026-05-17)
Relevant fields per program:
- `name`
- `url` — always `https://bugcrowd.com/engagements/<engagement-slug>` (all 218 programs in dump use this form). **Derive `engagement_slug` as the last path segment, then store the candidate slug as `bc-<engagement-slug>` (prefix is mandatory — see slug-prefix convention below).**
- `allows_disclosure` (bool)
- `managed_by_bugcrowd` (bool)
- `safe_harbor` (string: `"full"`, `"partial"`, `"none"`, or other)
- `max_payout` (int $ — can be `0` or `null` for programs without monetary bounty; treat `null` as `0`)
- `targets.in_scope[]` — each entry has `type`, `target`, `uri`, `name`, `ipAddress`
- `targets.out_of_scope[]` — same shape

The Bugcrowd dump does **NOT** include:
- `submission_state` (no paused/disabled flag — the dump only lists active programs)
- `offers_bounties` boolean (use `max_payout > 0` as the proxy)
- per-target severity or bounty eligibility
- **`SOURCE_CODE` as a target type** — Bugcrowd doesn't categorize repos in the dump. This means the strongest H1 OSINT signal (declared GitHub/GitLab repos) is unavailable to Bugcrowd scouting. Flag this gap in `summary.notes`.

`type` values seen in `targets.in_scope[]`: `website`, `api`, `other`, `network`, `ios`, `android`, `iot`, `hardware`, `ip_address`. (URL-domain assets are `website` + `api`. Wildcards live in the `target` string as `*.example.com` and similar — there is no dedicated wildcard type.)

#### Intigriti schema (confirmed 2026-05-18)
Relevant fields per program:
- `id` (UUID)
- `name`
- `company_handle`, `handle` (usually equal; use `handle` for slug)
- `url` — `https://www.intigriti.com/programs/<company_handle>/<handle>/detail`. **Derive `handle`, then store the candidate slug as `int-<handle>` (prefix is mandatory — same convention as `bc-` for Bugcrowd).**
- `status` — `"open"` only in dump (Intigriti only exposes open public programs)
- `confidentiality_level` — `"public"` only in dump
- `min_bounty.{value, currency}` and `max_bounty.{value, currency}` (currency ∈ {EUR, USD, GBP})
- `tacRequired`, `twoFactorRequired` (bool — record in notes; not used for scoring)
- `targets.in_scope[]` — each entry has `type`, `endpoint`, `description`, `impact`
- `targets.out_of_scope[]` — same shape

`type` values seen in Intigriti `targets.in_scope[]`: `url` (808), `wildcard` (412), `other` (100), `android` (66), `ios` (63), `iprange` (39), `device` (3), `null` (3). **Intigriti has a dedicated `wildcard` type** (cleaner than Bugcrowd, where wildcards live as `*` substrings in `target` strings).

`impact` tiers in Intigriti: `"Tier 1"` (261), `"Tier 2"` (494), `"Tier 3"` (153), `"No Bounty"` (417 — VDP-only assets within an otherwise-bounty program), `null` (169).

Severity mapping for scope ingest (program-scope-parser uses this; scout doesn't need it since scoring keys on raw tier counts):
- `Tier 1` → `critical` cap
- `Tier 2` → `high` cap
- `Tier 3` → `medium` cap
- `No Bounty` → `info` cap (VDP, not a bounty-eligible asset)
- `null` → `unknown`

The Intigriti dump does NOT include:
- `submission_state` (no `paused`/`disabled` flag — dump only carries open public programs)
- a `SOURCE_CODE` target type (same gap as Bugcrowd — flag in `summary.notes`)
- policy text

If any dump's schema changes upstream (new fields, removed fields), log it in `summary.notes` and the next retro can propose adjusting scoring.

### 3. List existing ingested programs (platform-aware)
```bash
ls memory/programs/*.json 2>/dev/null
```

For each JSON file, read `program.platform` and `program.slug`. Build `auto_exclude_set` containing every `program.slug` whose stored `program.platform` matches the current scout target. Combine with the input `exclude_slugs`.

**Important — slug-prefix convention:** Non-H1 platforms are stored with a per-platform prefix to avoid namespace collisions across platforms; HackerOne programs are unprefixed (legacy default). Scout's candidate slug must match what `program-load` would store:
- HackerOne candidates: `slug = handle` (e.g., `cloudflare`).
- Bugcrowd candidates: `slug = "bc-" + engagement_slug` (e.g., `bc-t-mobile`).
- Intigriti candidates: `slug = "int-" + handle` (e.g., `int-aikido`).

This way the exclusion check is a simple set membership test on the same prefixed form the parser uses.

(Cross-platform name collisions are intentional — e.g., a hypothetical `acme` Bugcrowd program (stored as `bc-acme`) is NOT excluded just because an `acme` H1 program is already ingested.)

### 4. Pre-filter
Platform-specific gates:

**HackerOne:**
- `submission_state == "open"`
- `offers_bounties == true`
- `handle` NOT in `auto_exclude_set`
- `critical_eligible_count >= min_critical_eligible` (count of `targets.in_scope[*]` entries with `eligible_for_bounty==true` AND `max_severity=="critical"`)
- `in_scope_count >= min_in_scope` (total `targets.in_scope[]` length)
- If `require_wildcard == true`: at least one `targets.in_scope[*]` has `asset_type == "WILDCARD"` (or `asset_type == "URL"` with `*` in `asset_identifier`)

**Bugcrowd:**
- `max_payout >= min_max_payout` (treat null as 0; default min_max_payout=1 means "must pay something")
- `bc-<engagement_slug>` NOT in `auto_exclude_set` (the candidate slug is the prefixed form; the auto-exclude set is built from stored `program.slug` values which are also prefixed)
- `in_scope_count >= min_in_scope` (total `targets.in_scope[]` length)
- If `require_wildcard == true`: at least one `targets.in_scope[*]` has `*` in its `target` string

**Intigriti:**
- `status == "open"` AND `confidentiality_level == "public"` (every program in the dump should already satisfy this; assert defensively)
- `max_payout_usd >= min_max_payout` where `max_payout_usd = max_bounty.value × {EUR: 1.07, GBP: 1.28, USD: 1.0}[max_bounty.currency]`. Treat missing `max_bounty` as `0`.
- `int-<handle>` NOT in `auto_exclude_set`
- `tier1_count >= min_tier1_count` where `tier1_count` = count of `targets.in_scope[*]` with `impact == "Tier 1"`
- `in_scope_count >= min_in_scope` (total `targets.in_scope[]` length)
- If `require_wildcard == true`: at least one `targets.in_scope[*]` has `type == "wildcard"` (Intigriti has a dedicated type, no need to substring-match `*`)

### 5. Score each surviving program
Compute an integer score by summing signal weights. All signals are derivable from the dump alone — no per-program HTTP calls.

The rubric is **dual-yield + triage-health (v3, 2026-06-19).** bb-agent is no longer passive-only: it now runs an **active web-vuln tier** (webvuln-surface → access-control-hunter for IDOR/BOLA/BFLA, plus the injection/auth class hunters) alongside the passive OSINT hunts (secrets / buckets / takeover). So the scout now optimizes for programs likely to yield reportables on **BOTH** axes, not just leaks. Three dimensions:

- **OSINT-leak** — declared source repos (secrets) + wildcard/surface breadth (buckets, takeover).
- **Web-vuln** — real web/API application surface to send the class hunters at. Wildcard and URL breadth feed this too; an explicit `API` asset type is the cleanest direct IDOR/BOLA signal where the dump exposes it.
- **Triage-health** — will the program actually engage and triage a report? `managed_*` (pro triage team / SLA) and (H1) `response_efficiency_percentage` are the dump's only honest proxies for the activity that "report count" stands in for. Surfaced because a high-yield finding into a ghost program (cf. automattic, 32 days no first response) is wasted work. For Bugcrowd, `safe_harbor` is promoted to a scored signal — it matters more now that we *actively* test, not just observe.

**A note on the factors that are NOT in any dump.** The arkadiyt dump exposes no report count, no resolved-report count, no bounty totals (only `max_payout` on BC/Intigriti), and no company-size field. So "how many reports" and "company size" cannot be scored directly — triage-health proxies the former; surface breadth (`in_scope_count`/`url_domain_count`) is the only size proxy. We deliberately do **not** reward raw bigness: bb-agent's own history (the clean-negative club — netflix, valve, opera, okg, dynatrace, slack — all large, all 0 reports) shows large + polished correlates with *tighter hygiene*, i.e. lower yield. Size therefore enters only as the validated **inverted** tiebreak (smaller = less picked-over; see Step 6), never as a positive score. See `memory/feedback_program_scout_rubric.md`, `memory/feedback_program_scout_rubric_bugcrowd.md`, `memory/feedback_target_pick_yield.md`.

**Signal-string convention:** every fired signal is recorded as a `<dimension>:<name>` string so the ranking is auditable by dimension — `osint:*`, `web:*`, `surface:*` (counts toward both OSINT and web), `value:*`, `triage:*`, `quality:*`, plus the bare `dual_yield` bonus.

#### HackerOne rubric (max score 15)

**OSINT-leak:**

| Signal string | Weight |
|---|---|
| `osint:has_source_code` — has `SOURCE_CODE` in-scope | +4 |

**Attack-surface breadth (feeds OSINT *and* web):**

| Signal string | Weight |
|---|---|
| `surface:has_wildcard` (`asset_type=WILDCARD` or URL containing `*`) | +2 |
| `surface:url_domain>=10` (count of `asset_type` in {`URL`, `WILDCARD`, `API`}) | +1 |
| `surface:url_domain>=30` | +1 (additional) |
| `surface:in_scope>=50` | +1 |
| `surface:in_scope>=200` | +1 (additional) |

**Web-vuln:**

| Signal string | Weight |
|---|---|
| `web:has_api` — ≥1 in-scope asset with `asset_type == "API"` (explicit IDOR/BOLA surface) | +1 |

**Triage-health:**

| Signal string | Weight |
|---|---|
| `triage:managed` — `managed_program == true` (H1-managed triage team / SLA) | +1 |
| `triage:resp_eff>=90` — `response_efficiency_percentage >= 90` (reliably responds; avoids ghost programs) | +1 |

**Dual-yield bonus:**

| Signal string | Weight |
|---|---|
| `dual_yield` — `osint:has_source_code` fired **AND** (`surface:url_domain>=10` OR `surface:has_wildcard`) — declared repos (secret-leak surface) stacked on a real web/infra footprint = both the OSINT hunts and the web-vuln tier have material to work with | +2 |

H1 web surface ≈ URL/WILDCARD density (the dump folds most APIs into `URL`; only ~30 assets dump-wide carry the explicit `API` type), so the web axis mostly reuses the `surface:*` signals; `web:has_api` is a bonus when the program declares APIs explicitly.

#### Bugcrowd rubric (max score 14)

Bugcrowd's dump lacks `SOURCE_CODE` typing, so the strongest H1 OSINT signal is unavailable — flag this gap (caveat below). But Bugcrowd uniquely exposes a dedicated **`api` target type**, the cleanest direct IDOR/BOLA/BFLA signal for the web-vuln tier, so the web axis is *better* served here than on H1. Bugcrowd-scored programs are not directly comparable to H1-scored programs.

**Attack-surface breadth (feeds OSINT *and* web):**

| Signal string | Weight |
|---|---|
| `surface:has_wildcard` (`*` in any `targets.in_scope[*].target`) | +2 |
| `surface:url_domain>=10` (count of `type` in {`website`, `api`}) | +1 |
| `surface:url_domain>=30` | +1 (additional) |
| `surface:in_scope>=50` | +1 |
| `surface:in_scope>=200` | +1 (additional) |

**Web-vuln:**

| Signal string | Weight |
|---|---|
| `web:has_api` — ≥1 in-scope target with `type == "api"` | +2 |

**Triage-health / quality (soft):**

| Signal string | Weight |
|---|---|
| `triage:managed` — `managed_by_bugcrowd == true` | +1 |
| `triage:safe_harbor_full` — `safe_harbor == "full"` (legal cover for active testing — promoted to scored now that we send payloads, not just observe) | +1 |
| `quality:max_payout>=5000` | +1 |
| `quality:max_payout>=10000` | +1 (additional) |

**Dual-yield bonus:**

| Signal string | Weight |
|---|---|
| `dual_yield` — `web:has_api` fired **AND** `surface:has_wildcard` fired (API = web/IDOR anchor; wildcard = infra-leak/takeover anchor) | +2 |

**Always set `summary.notes` to include this caveat when `platform=bugcrowd`:**
> "Bugcrowd's dump does not expose SOURCE_CODE target type. The strongest OSINT signal (declared GitHub/GitLab repos) is unavailable to scout. Manually search GitHub for the company name on each candidate before running /hunt-secrets."

#### Intigriti rubric (max score 13)

Intigriti has the richest signal of the three platforms — per-target impact tier (like H1), max_payout (like Bugcrowd), and a dedicated `wildcard` type — but no `SOURCE_CODE` target type and (unlike H1/BC) **no triage-health field** (no managed flag, no response metrics; `tacRequired`/`twoFactorRequired` are recorded in notes but aren't triage-quality). The `value:has_tier1` signal does double duty: a Tier-1 critical-equivalent asset is both bb-agent's per-target severity proxy *and* a crown-jewel web app worth the class hunters' time.

**Value / OSINT proxy (no SOURCE_CODE in dump):**

| Signal string | Weight |
|---|---|
| `value:has_tier1` — `tier1_count >= 1` (≥1 Tier 1 critical-equivalent asset) | +3 |

**Attack-surface breadth (feeds OSINT *and* web):**

| Signal string | Weight |
|---|---|
| `surface:has_wildcard` (`type == "wildcard"` on at least one in-scope target) | +2 |
| `surface:url_domain>=10` (count of `type` in {`url`, `wildcard`}) | +1 |
| `surface:url_domain>=30` | +1 (additional) |
| `surface:in_scope>=50` | +1 |
| `surface:in_scope>=200` | +1 (additional) |

**Quality (soft):**

| Signal string | Weight |
|---|---|
| `quality:max_payout>=5000` (USD-normalized) | +1 |
| `quality:max_payout>=10000` | +1 (additional) |

**Dual-yield bonus:**

| Signal string | Weight |
|---|---|
| `dual_yield` — `value:has_tier1` fired **AND** `surface:has_wildcard` fired (Tier-1 crown-jewel app for the web tier; wildcard = infra-leak/takeover surface for OSINT) | +2 |

**Always set `summary.notes` to include this caveat when `platform=intigriti`:**
> "Intigriti's dump does not expose SOURCE_CODE target type. The strongest OSINT signal (declared GitHub/GitLab repos) is unavailable to scout. Manually search GitHub for the company name on each candidate before running /hunt-secrets. The dump also carries no triage-health field, so triage quality is not scored on Intigriti — check the live program page."

Scores across platforms are not directly comparable: H1 max 15, Intigriti max 13, Bugcrowd max 14.

### 5.5. Company dedup (Intigriti only)
If `platform == "intigriti"` AND `company_dedup == true` (default), group scored candidates by `company_handle` and keep only the highest-scored entry per company. Within a company, break ties using the same tiebreak order as Step 6 (dual_yield desc, wildcard_count desc, url_domain_count desc, in_scope_count asc, handle asc). Record the dedup in `summary.notes` like `"company_dedup folded 4 aswatson siblings (kept watsons; dropped marionnaud, kruidvat, perfumeshop)"` so the user can see what was hidden.

On H1 and Bugcrowd this step is a no-op (those dumps don't expose a parent-company field; fuzzy-name matching would be guesswork). Mention this once in `summary.notes` if the user passed `company_dedup=false` explicitly — that flag has no effect outside Intigriti.

### 6. Rank and pick top N
Sort by:
1. `score` desc
2. **`dual_yield` desc** (true before false) — a program with material on *both* the OSINT and web axes is the explicit target of this rubric, so it wins same-score ties decisively over a program that scored the same on a single axis. (The +2 bonus already nudges score; this key guarantees the tiebreak.)
3. **`wildcard_count` desc** — wildcards predict takeover surface (every wildcard expands to dozens-of-subdomains worth of dangling-CNAME opportunities), bucket-name derivation surface (every wildcard adds a base_name), AND web attack surface (more live subdomains = more endpoints for the class hunters). Strongest single cross-axis predictor.
4. **`url_domain_count` desc** — more URL/WILDCARD/API assets = more bucket-name and takeover candidates AND more web endpoints to test.
5. **`in_scope_count` asc** — smaller scopes correlate with "younger, less picked-over" programs. This is the *only* place company-size enters the ranking, and it enters **inverted on purpose**: bb-agent's history (the clean-negative club: netflix/valve/opera/okg/dynatrace/slack — all large, all 0 reports) plus [[project_toolsforhumanity_engagement]] (younger program yielded a submitted report) and [[feedback_target_pick_yield]] show large+polished correlates with tighter hygiene = lower yield. We never reward raw bigness.
6. `slug` asc (final deterministic tiebreak)

Take top `top_n`. The tiebreak shifts in (2)–(5) make the #1 position "highest probability to report something on either axis" rather than "highest raw score with arbitrary alphabetical winner". Programs at the same score are ordered by predicted dual-yield, not by name.

Note that the **v3 rubric (2026-06-19)** re-bases scores (new max per platform) and adds `dual_yield` as the #2 sort key, so ranks AND scores are not comparable to any pre-v3 scout output. The output JSON includes the full sort key tuple per candidate so the ranking is auditable.

### 7. Write output
Path: `out/scout/<UTC-YYYYMMDD-HHMMSS>.json` (mkdir -p the dir; file mode 0644 is fine — no secrets in this file).

Schema:
```json
{
  "generated_at": "<UTC ISO8601>",
  "platform": "hackerone",
  "data_source": "arkadiyt/bounty-targets-data (hackerone_data.json)",
  "filters_applied": { /* echo of input with defaults filled in */ },
  "directory_total": 0,
  "pre_filtered": 0,
  "scored": 0,
  "auto_excluded": ["mercadolibre", "greenhouse", "8x8-bounty", "semrush"],
  "candidates": [
    {
      "rank": 1,
      "slug": "shopify",
      "platform": "hackerone",
      "url": "https://hackerone.com/shopify",
      "name": "Shopify",
      "score": 13,
      "dual_yield": true,
      "sort_key": [13, true, 3, 35, 87, "shopify"],
      "sort_key_meaning": "[score, dual_yield, wildcard_count, url_domain_count, in_scope_count, slug]",
      "signals": [
        "osint:has_source_code",
        "surface:has_wildcard",
        "surface:url_domain>=10",
        "surface:url_domain>=30",
        "surface:in_scope>=50",
        "triage:managed",
        "triage:resp_eff>=90",
        "dual_yield"
      ],
      "bounty": {
        "offers_bounties": true,
        "critical_eligible_count": 73
      },
      "triage": {
        "managed_program": true,
        "response_efficiency_percentage": 96,
        "average_time_to_first_program_response": 3600
      },
      "in_scope_summary": {
        "total": 87,
        "wildcards": 3,
        "urls": 35,
        "api": 0,
        "mobile": 2,
        "source_code": 2,
        "other": 45
      },
      "next_commands": [
        "/program-load https://hackerone.com/shopify",
        "/hunt-secrets shopify",
        "/hunt-buckets shopify",
        "/webvuln-surface shopify"
      ]
    }
  ],
  "summary": {
    "notes": ""
  }
}
```

**Shared new fields (all platforms):**
- `dual_yield` (bool) — top-level on every candidate; mirrors whether the `dual_yield` signal fired.
- `sort_key` now carries `dual_yield` in position 2: `[score, dual_yield, wildcard_count, url_domain_count, in_scope_count, slug]`. Keep `sort_key_meaning` in sync.
- `in_scope_summary.api` — count of explicit API-typed assets (`asset_type=="API"` on H1; `type=="api"` on Bugcrowd; always `0` on Intigriti, no dedicated api type).
- `next_commands` includes the web-vuln tier entry point `"/webvuln-surface <slug>"` as a 4th line for **dual_yield** candidates (and any candidate with web surface). It's the doorway to the active class hunters (access-control etc.); the OSINT hunts (`/hunt-secrets`, `/hunt-buckets`) stay listed for the leak axis.

**Platform-specific field shapes:**
- `data_source` reflects which dump was fetched (`hackerone_data.json`, `bugcrowd_data.json`, or `intigriti_data.json`).
- `platform` is set at the top level AND on every candidate.
- For **HackerOne** candidates, include the `triage` block:
  ```json
  "triage": {
    "managed_program": true,
    "response_efficiency_percentage": 96,
    "average_time_to_first_program_response": 3600
  }
  ```
  (`average_time_to_first_program_response` is informational — not scored.)
- For **Bugcrowd** candidates:
  - `bounty` becomes `{ "max_payout": 5000, "safe_harbor": "full", "managed_by_bugcrowd": true }`.
  - `triage` block: `{ "managed_by_bugcrowd": true, "safe_harbor": "full" }` (the two scored triage/quality signals).
  - `in_scope_summary`: mobile = count of `type` in {`ios`, `android`}, urls = count of `type` in {`website`, `api`}, `api` = count of `type == "api"`, wildcards = count of entries with `*` in `target`. `source_code` is always `0`.
  - `slug` is the prefixed form `bc-<engagement_slug>`; `url` is the canonical `https://bugcrowd.com/engagements/<engagement_slug>`.
  - `next_commands`:
    ```json
    "next_commands": [
      "/program-load https://bugcrowd.com/engagements/t-mobile",
      "/hunt-secrets bc-t-mobile",
      "/hunt-buckets bc-t-mobile",
      "/webvuln-surface bc-t-mobile"
    ]
    ```
- For **Intigriti** candidates:
  - `slug` is the prefixed form `int-<handle>`; `url` is the canonical `https://www.intigriti.com/programs/<company_handle>/<handle>/detail`.
  - `bounty`: `{ "max_payout": 2500, "max_payout_currency": "EUR", "max_payout_usd": 2675, "tier1_count": 4 }`.
  - No `triage` block (dump carries no triage-health field); note this once in `summary.notes`.
  - `in_scope_summary`: `wildcards` = count of `type == "wildcard"`, `urls` = count of `type == "url"`, `api` = `0`, `mobile` = count of `type` in {`android`, `ios`}, `source_code` = 0, `other` = remainder.
  - `next_commands`:
    ```json
    "next_commands": [
      "/program-load https://www.intigriti.com/programs/aikido/aikido/detail",
      "/hunt-secrets int-aikido",
      "/hunt-buckets int-aikido",
      "/webvuln-surface int-aikido"
    ]
    ```

### 8. Report back
Reply to the parent with:
- output file path
- platform scouted
- counts: directory_total / pre_filtered / scored / returned
- top 3 candidates as `rank. slug @ score (dual✓/single) — top-signals` — call out whether each is dual-yield and which axes its signals cover (OSINT / web / triage).
- a single reminder line: human picks winners and runs `/program-load <url>` then the OSINT hunts (`/hunt-secrets`, `/hunt-buckets`) **and** the web-vuln tier entry `/webvuln-surface <slug>`. Scout does NOT ingest.
- If platform was Bugcrowd or Intigriti, surface the SOURCE_CODE caveat so the user knows to pair with manual GitHub search. For Intigriti, also note triage-health is unscored (not in dump).
- Reminder that account-creatability — the real gate for *active* web testing (cf. [[project_int_kruidvat]], [[project_int_wolt]]) — is NOT in the dump and isn't scored. Flag it as a thing to confirm on the program page for any pick the user wants to push into the web-vuln tier; do not pre-filter on it (see [[feedback_account_availability_not_a_filter]]).

## Don'ts
- Don't `/program-load` anything yourself.
- Don't make >1 outbound HTTP call (just the dump fetch — one platform per invocation).
- Don't fetch a program-owned asset — not even a HEAD request.
- Don't enumerate GitHub orgs (defer to a future version).
- Don't include private / invite-only programs (won't be in the public dump anyway).
- Don't include H1 programs with `submission_state != "open"`.
- Don't compare scores across platforms — the rubrics differ (Bugcrowd max 7, H1 max 10, Intigriti max 11). Scores are intra-platform rankings only.
- Don't add fields outside the output schema. Use `summary.notes` (string) for anything else.
