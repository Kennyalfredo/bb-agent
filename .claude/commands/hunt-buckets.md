---
description: Enumerate cloud buckets for an ingested program (listing-only, no GetObject). Writes candidates to out/<slug>/buckets/<ts>.json. Does NOT verify ownership.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off bucket enumeration for program slug: $ARGUMENTS

Delegate to the `bucket-hunter` subagent. Pass the slug and require it to:
1. Read `memory/programs/<slug>.json`; abort if `rules.bucket_listing_allowed` is `false`.
2. Derive base names from in-scope wildcards/domains (strip public suffix, take leftmost label).
3. Run domain-derived candidate scan via `s3scanner`; fall back to `cloud_enum` only if zero hits.
4. Step 4.5 (mandatory): for every s3scanner-flagged candidate, run `aws s3api list-objects-v2 --no-sign-request --bucket <n> --max-items 1` once and record the authoritative result in `acl_recheck`. Drives the rule `s3scanner_acl_recheck_required` — defangs the snapchat/automattic/opera-style ALLOWED-but-AccessDenied FP pattern (11+ buckets observed across those engagements).
5. Write `out/<slug>/buckets/<UTC-ts>.json` per the agent's declared schema.

When the subagent returns, give the user a tight summary:
- output file path
- # candidates scanned, # s3scanner-flagged, **# acl_recheck verified_listable** (the only count that can become a critical report), whether Pass B (cloud_enum) ran
- # FPs caught by acl_recheck (s3scanner ALLOWED → aws AccessDenied)
- the next command per **verified-listable** hit: `/verify-ownership <slug> <bucket-name>`. Do NOT recommend verify-ownership on `acl_recheck.verified_listable == false` candidates — they cannot become a public-read report.

Reminder to the user: every verified-listable hit is **UNVERIFIED with respect to ownership**. No report drafting until `ownership-verifier` says `owned`.
