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
4. Write `out/<slug>/buckets/<UTC-ts>.json` per the agent's declared schema.

When the subagent returns, give the user a tight summary:
- output file path
- # candidates scanned, # bucket hits, whether Pass B (cloud_enum) ran
- the next command per hit: `/verify-ownership <slug> <bucket-name>`

Reminder to the user: every hit is **UNVERIFIED**. No report drafting until `ownership-verifier` says `owned`.
