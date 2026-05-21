---
description: Ingest a HackerOne, Bugcrowd, or Intigriti program page into memory/programs/<slug>.json
argument-hint: <hackerone-bugcrowd-or-intigriti-url>
allowed-tools: Agent
---

You are kicking off program ingestion for: $ARGUMENTS

Supported URL forms:
- `https://hackerone.com/<handle>` — stored as `memory/programs/<handle>.json` (no prefix)
- `https://bugcrowd.com/engagements/<engagement-slug>` — stored as `memory/programs/bc-<engagement-slug>.json` (the `bc-` prefix is mandatory)
- `https://www.intigriti.com/programs/<company-handle>/<handle>/detail` — stored as `memory/programs/int-<handle>.json` (the `int-` prefix is mandatory)

See `memory/feedback_bugcrowd_slug_prefix.md` for the prefix convention rationale (same logic extends to `int-`).

Delegate this to the `program-scope-parser` subagent. Pass the URL and instruct it to:
1. Validate the URL (must be hackerone.com, bugcrowd.com, or intigriti.com).
2. Fetch the policy/scope page(s). For Bugcrowd and Intigriti, the structured scope/bounty data is reliably in the arkadiyt/bounty-targets-data dump — parser pulls from there (same source program-scout uses). No program-owned asset fetch.
3. Produce a JSON conforming to its declared schema, with `program.slug` set to the prefixed form for Bugcrowd / Intigriti.
4. Write it to `/home/kenny/bb-agent/memory/programs/<slug>.json`.

When the subagent returns, give the user a tight summary:
- slug (with platform prefix if applicable) + file path + platform
- in-scope count, out-of-scope count
- bounty tier (`bug_bounty` / `vdp` / `unknown`)
- any rules that were set by safe-default (so the user can disambiguate them now if desired)
- if Bugcrowd: flag that per-target `severity_cap` defaults to `unknown` for all assets — refine before drafting medium/low severity reports
- if Intigriti: flag the Tier 1/2/3 → critical/high/medium mapping, and that `No Bounty` assets are capped at `info` (VDP-only within bounty program) — confirm before drafting
- next commands the user can run: `/hunt-secrets <slug>`, `/hunt-buckets <slug>`, and `/hunt-takeovers <slug>` (use the prefixed slug for Bugcrowd / Intigriti)

Do not run any recon tools or fetch anything other than the policy page (and the public bounty-targets-data dump for Bugcrowd / Intigriti fallback).
