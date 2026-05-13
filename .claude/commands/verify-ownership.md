---
description: Verify an asset (bucket/subdomain/IP) belongs to a program before drafting a report. Returns owned|unowned|unknown with evidence. Caches under memory/ownership-cache/.
argument-hint: <program-slug> <asset>
allowed-tools: Agent
---

You are kicking off ownership verification.
Arguments: $ARGUMENTS  (expected: `<slug> <asset>`)

Delegate to the `ownership-verifier` subagent. Pass both arguments and require it to:
1. Check the 30-day cache first (`memory/ownership-cache/<sha1>.json`); short-circuit if fresh.
2. Run three independent **indirect** checks:
   - GitHub code search (`gh api search/code`)
   - Wayback / OTX archive presence (`gau` against program in-scope domains)
   - DNS chain (`dnsx`, `dig`) for subdomains; inconclusive for raw bucket names without a CNAME
3. Aggregate via the 2-of-3 rule. Never conclude `owned` from a single positive signal.
4. Write the verdict + evidence to `memory/ownership-cache/<sha1>.json`.

When the subagent returns, relay to the user:
- verdict (`owned` / `unowned` / `unknown`)
- one line summarizing the three check statuses
- cache file path
- if not `owned`: **"DO NOT draft a report against this asset."**

Reminder: this subagent must NEVER touch the asset directly (no curl, no nuclei, no httpx).
