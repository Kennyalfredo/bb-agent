# bb-agent — Tier-3 bug bounty hunting agent

Multi-subagent system for Claude Code that automates non-applicative bug bounty
discovery (leaked credentials, exposed cloud assets, subdomain takeover)
across HackerOne / Bugcrowd programs that have similar rules to MELI's Tier 3.

## Status

- **Day 1 (2026-05-11) — DONE** — Tool environment installed, project scaffolded
- **Day 2 (2026-05-12) — DONE** — `/program-load` slash command + `program-scope-parser` subagent; MELI ingested at `memory/programs/mercadolibre.json` (68 in-scope, 10 out-of-scope, bug_bounty tier)
- **Day 3 (2026-05-13) — DONE** — `bucket-hunter` and `ownership-verifier` subagents (independent, decoupled). `/hunt-buckets <slug>` does domain-derived candidates → s3scanner Pass A → cloud_enum Pass B fallback. `/verify-ownership <slug> <asset>` runs 3 indirect checks (gh code search, gau Wayback, dnsx) with 2-of-3-positive rule and 30-day cache under `memory/ownership-cache/`. Smoke-tested against MELI: 16 candidate bucket hits; verifier correctly returned `unowned` on `mercadolivre` (the README's wasted-day asset) and conservative `unknown` on the brand-stem `mercadolibre`.
- **Day 4 (2026-05-13) — DONE** — `secret-hunter` subagent + `/hunt-secrets` slash command. Full pipeline: Pass A `trufflehog github --results=verified` per derived GH org (≤3 default, ≤1 strict); Pass B one `gh api search/code` per base name (≤6/≤3) → shallow-clone top hits to `/mnt/files/bb-agent/<slug>/secrets/clones/` → `trufflehog filesystem --results=verified` per repo; Pass C `noseyparker scan` with full history into a shared datastore + one `report --format json`. Output is redacted (4-prefix/4-suffix) candidate JSON to `out/<slug>/secrets/<ts>.json` (mode 0600); raw evidence stays under `/mnt/files/...` (0700). Decoupled from ownership-verifier (verifies the *repo owner*, not the asset) and from drafting. Smoke-tested against MELI: 1 org / 3 codesearch calls / 3 repos cloned / 0 verified candidates / 1 noseyparker false-positive (literal `password="False"` in an Odoo XML config) — pipeline behaved correctly. Tools.md flag for trufflehog corrected from the old `--only-verified` to the 3.95.x `--results=verified`.
- **Day 5** — `report-drafter` + memory wiring

## Directory layout

```
bb-agent/
├── README.md             — this file
├── tools.md              — binary inventory (full paths, versions, compliance rules)
├── .claude/
│   ├── agents/           — subagent definitions (.md files with frontmatter)
│   ├── commands/         — slash commands (e.g., /program-load, /tier3-hunt)
│   └── skills/           — reusable knowledge (e.g., tier3-rules)
├── memory/
│   ├── programs/         — per-program scope JSON (mercadolibre.json, openai.json, ...)
│   └── ownership-cache/  — ownership-verification cache (positive + negative)
└── out/                  — scan outputs, drafted reports
```

Note: bbot scan output goes to `/mnt/files/bb-agent/` (off-root partition),
NOT here. This dir is only for agent state + reports.

## Key architectural decisions

1. **Many small subagents, not one big one.** Each has restricted tools.
2. **Ownership verifier is mandatory before drafting.** Skipping it cost us a wasted day on the `mercadolivre.s3.amazonaws.com` bucket.
3. **One non-destructive validation call per finding source.** Tracked in state.
4. **No auto-submit.** Reports go to `out/<program>/reports/*.md`. Human submits.
5. **Per-program rule parsing.** Each program's restrictions become machine-readable
   flags that downstream subagents respect.

## Running anything

To use the agent from Claude Code:

```bash
cd ~/bb-agent
claude
```

Then invoke slash commands like `/program-load <h1-url>` once they're built.

## Compliance rules (read tools.md for full list)

- No active mass scanning
- One validation call per source
- No bucket file downloads
- Verify ownership BEFORE drafting report
- 0-day age gate (≥30 days since publication)
