---
description: Hunt publicly-exposed sensitive endpoints and files for an ingested program (/.env*, /config.*, /.git/HEAD, /swagger*, /actuator/env, etc.). Passive enumeration via gau; OPTIONAL active live-probe via httpx + nuclei gated on automated_tools_allowed=true AND explicit_scanner_ban != true. Writes redacted candidates to out/<slug>/endpoints/<ts>.json. Does NOT verify ownership.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off endpoint-disclosure hunting for program slug: $ARGUMENTS

Delegate to the `endpoint-hunter` subagent. Pass the slug and require it to:
1. Read `memory/programs/<slug>.json`. **REFUSE TO RUN if `rules.explicit_scanner_ban == true`** — write an empty-candidates output file with `refused_reason: "explicit_scanner_ban=true"` and stop. Same hard-gate semantics as `rule-takeover_hunter-refuse_if_explicit_scanner_ban-739e9`. If `rules.automated_tools_allowed == false`, run in `passive_only_mode` — Steps 4-5 (gau + grep) only; Steps 6-8 (httpx + body fetch + nuclei) skipped. If `rules.rate_limit_cap_rps` is set, pass through to httpx/nuclei as `-rate-limit`; default 5 req/sec.
2. Derive seed domains from in-scope wildcards/domains (cap 10 default / 3 strict).
3. Step 4 — gau passive URL enumeration against each seed (Wayback + CommonCrawl + AlienVault OTX + URLScan). No HTTP requests against the program's own infrastructure during this step.
4. Step 5 — grep curated sensitive-path patterns from the URL corpus across 9 categories: env_file, config_file, backup, vcs, server_info, api_docs, admin, monitoring, hidden_file. Apply `rules.endpoint_hunter.path_glob_skip[]` filters. Cap at 2000 candidates default / 200 strict.
5. Step 6 (GATED) — httpx live probe of candidates. Records `live_status`, `content_length`, `content_type`, `title`. Only confirmed `200 OK` URLs proceed to body fetch.
6. Step 7 (GATED) — single-curl body fetch (capped at 64 KB via `--max-filesize 65536` — hard rule, never violate). Per-category signature matching: env-var pattern for `.env`, JSON config keys for config files, `^ref: refs/heads/` for `/.git/HEAD`, `propertySources` for actuator/env, etc. Apply `rules.endpoint_hunter.body_signature_skip[]` filters.
7. Step 8 (GATED) — nuclei second-engine pass with `http/exposures/` + `http/misconfiguration/` templates only. Multi-engine corroboration boosts candidate confidence.
8. Write redacted candidate JSON to `out/<slug>/endpoints/<UTC-ts>.json`.

When the subagent returns, give the user a tight summary:
- output file path (or `refused_reason` if the explicit-scanner-ban gate fired)
- the funnel: `urls_enumerated → sensitive_candidates → httpx_live_200 → body_signatures_matched → candidates_high_confidence`
- nuclei gating decision (`ran` / `skipped: <reason>`) and finding count if it ran
- `passive_only_mode` status (true/false) — if true, the candidate list is unprobed (gau+grep only); operator needs to know the live-status fields are placeholders
- top 3 candidates as `url [category] (confidence=<level>, engines=[...])` — multi-engine candidates first
- the next command per unique subdomain in the candidates list: `/verify-ownership <slug> <subdomain>`. The `in_scope_subdomain_override` rule should auto-fire since the subdomain falls under a declared wildcard.

Reminder to the user: every candidate is **UNVERIFIED with respect to ownership** until ownership-verifier confirms. AND: detection is the report; do NOT manually dump full `/.env` contents, download `/.git` trees, or trigger `/actuator/heapdump` to "prove" the finding — body excerpt + content-length + signature match is sufficient evidence for the report-drafter. Exploitation is a separate concern out of bb-agent scope.
