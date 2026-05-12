---
description: Ingest a HackerOne or Bugcrowd program page into memory/programs/<slug>.json
argument-hint: <hackerone-or-bugcrowd-url>
allowed-tools: Agent
---

You are kicking off program ingestion for: $ARGUMENTS

Delegate this to the `program-scope-parser` subagent. Pass the URL and instruct it to:
1. Validate the URL (must be hackerone.com or bugcrowd.com).
2. Fetch the policy/scope page(s).
3. Produce a JSON conforming to its declared schema.
4. Write it to `/home/kenny/bb-agent/memory/programs/<slug>.json`.

When the subagent returns, give the user a tight summary:
- slug + file path
- in-scope count, out-of-scope count
- bounty tier (`bug_bounty` / `vdp` / `unknown`)
- any rules that were set by safe-default (so the user can disambiguate them now if desired)

Do not run any recon tools or fetch anything other than the policy page itself.
