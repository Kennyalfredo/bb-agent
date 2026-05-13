---
description: Hunt leaked credentials for an ingested program (verified-only trufflehog + GH code search + noseyparker historical). Writes redacted candidates to out/<slug>/secrets/<ts>.json. Does NOT verify the secret is owned by the program — that's the next step.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off leaked-credential hunting for program slug: $ARGUMENTS

Delegate to the `secret-hunter` subagent. Pass the slug and require it to:
1. Read `memory/programs/<slug>.json`; apply strict caps if both `automated_tools_allowed` and `mass_scanning_allowed` are `false`.
2. Derive GH org candidates and base names from in-scope wildcards/domains (strip public suffix, take leftmost label).
3. Pass A — `trufflehog github --org=<org> --only-verified --json` on each org candidate (≤3 default, ≤1 strict).
4. Pass B — one `gh api search/code` call per base name (≤6 default, ≤3 strict), pick ≤5 unique repos (≤3 strict), shallow-clone to `/mnt/files/bb-agent/<slug>/secrets/clones/`, run `trufflehog filesystem --only-verified` once per repo.
5. Pass C — unshallow each cloned repo, run `noseyparker scan` into a shared datastore, then `noseyparker report --format json` once.
6. Write redacted candidates to `out/<slug>/secrets/<UTC-ts>.json` (mode 0600). Raw evidence stays under `/mnt/files/bb-agent/<slug>/secrets/<ts>/` (mode 0700).

When the subagent returns, give the user a tight summary:
- output file path
- orgs scanned (Pass A), repos cloned (Pass B), Pass C run y/n
- `candidates_verified` and `candidates_total`
- top 3 verified candidates as `detector @ repo/path` (no secret values)
- the next command per unique repo owner: `/verify-ownership <slug> <repo-owner>`

Reminder to the user: every candidate is **UNVERIFIED** with respect to program ownership. A verified-by-issuer secret in a third-party fork is NOT a finding against the program until `ownership-verifier` confirms the repo owner is theirs. No report drafting until then.
