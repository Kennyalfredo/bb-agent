# bb-agent — Tier-3 bug bounty hunting agent

Multi-subagent system for Claude Code that automates non-applicative bug bounty
discovery (leaked credentials, exposed cloud assets, subdomain takeover)
across HackerOne / Bugcrowd programs that have similar rules to MELI's Tier 3.

## Status

- **Day 1 (2026-05-11) — DONE** — Tool environment installed, project scaffolded
- **Day 2 (2026-05-12) — DONE** — `/program-load` slash command + `program-scope-parser` subagent; MELI ingested at `memory/programs/mercadolibre.json` (68 in-scope, 10 out-of-scope, bug_bounty tier)
- **Day 3 (2026-05-13) — DONE** — `bucket-hunter` and `ownership-verifier` subagents (independent, decoupled). `/hunt-buckets <slug>` does domain-derived candidates → s3scanner Pass A → cloud_enum Pass B fallback. `/verify-ownership <slug> <asset>` runs 3 indirect checks (gh code search, gau Wayback, dnsx) with 2-of-3-positive rule and 30-day cache under `memory/ownership-cache/`. Smoke-tested against MELI: 16 candidate bucket hits; verifier correctly returned `unowned` on `mercadolivre` (the README's wasted-day asset) and conservative `unknown` on the brand-stem `mercadolibre`.
- **Day 4 (2026-05-13) — DONE** — `secret-hunter` subagent + `/hunt-secrets` slash command. Full pipeline: Pass A `trufflehog github --results=verified` per derived GH org (≤3 default, ≤1 strict); Pass B one `gh api search/code` per base name (≤6/≤3) → shallow-clone top hits to `/mnt/files/bb-agent/<slug>/secrets/clones/` → `trufflehog filesystem --results=verified` per repo; Pass C `noseyparker scan` with full history into a shared datastore + one `report --format json`. Output is redacted (4-prefix/4-suffix) candidate JSON to `out/<slug>/secrets/<ts>.json` (mode 0600); raw evidence stays under `/mnt/files/...` (0700). Decoupled from ownership-verifier (verifies the *repo owner*, not the asset) and from drafting. Smoke-tested against MELI: 1 org / 3 codesearch calls / 3 repos cloned / 0 verified candidates / 1 noseyparker false-positive (literal `password="False"` in an Odoo XML config) — pipeline behaved correctly. Tools.md flag for trufflehog corrected from the old `--only-verified` to the 3.95.x `--results=verified`.
- **Day 5 (2026-05-13) — DONE** — `report-drafter` subagent + `/draft-report` slash command + audit-trail wiring under `memory/submissions/<slug>.json`. Hard-refuses unless `ownership-verifier`'s cache says `verdict == owned` AND `fetched_at` is within 30 days; no override flag for `unknown`. Two modes: `/draft-report <slug>` enumerates every draftable candidate (cross-referenced against ownership cache + submissions audit-trail) and returns three lists (Draftable now / Needs ownership verification / Cannot draft) without auto-picking; `/draft-report <slug> <asset>` drafts one report. Severity = `min(class-default, scope.in_scope[*].severity_cap)`. Refuses noseyparker-only (unverified) secret candidates — they go to manual triage. Bucket-exposure and leaked-secret markdown templates use only the redacted prefix from the candidate JSON; raw secrets never leave `/mnt/files/...`. Audit trail at `memory/submissions/<slug>.json` (tracked in git) records `submitted: false` until the human pastes the report and flips it. Smoke-tested against MELI: list mode correctly emitted 0 Draftable / 15 Needs verification / 2 Cannot draft (the cached `mercadolibre`=unknown and `mercadolivre`=unowned); explicit refusal on `mercadolibre` verbatim, no files written. Day 5 fix list (6 doc inconsistencies caught by the smoke) folded back into the agent before commit.
- **Day 6 (2026-05-13) — DONE** — Learning loop v1: `retro-analyzer` subagent + `/retro` slash command + `memory/lessons.md` (narrative journal) + `memory/rules.json` (machine-readable rules per subagent). `/retro <slug>` walks engagement artifacts (out/, ownership-cache/, submissions) and runs 5 heuristics (noseyparker FPs, brand-stem Wayback degeneracy, mature-org Pass A downweight, bare-brand bucket inconclusive, platform-dismissed reports) → writes a proposal to `memory/lessons/proposals/<ts>-<slug>.json` with ≤5 candidate rules, each with deterministic `rule-<agent>-<path>-<5char-hash>` IDs and `low`/`medium` confidence (v1 ceiling). Never mutates active state. `/retro apply <proposal-id> [rule-ids...]` commits selected rules to `rules.json` with full `id/added/from_engagement/confidence/reason` provenance and appends the narrative to `lessons.md`. Refuses partial-allowlist with unknown IDs. The four existing agents got a tiny step-0 preamble that reads their `rules.<agent-name>` slice and applies it inline. Smoke against MELI proposed 3 rules (Generic Password FP `low`; Wayback `word_boundary` `medium`; brand-stem bucket skip `low`) + a narrative; selective apply of the Wayback rule landed it cleanly with provenance, the two unselected rules stayed unchanged. Day 6 fix list (8 papercuts: rule-ID hash determinism, allowlist validation, narrative-header ownership, consumer schema for `detector_ignore`, etc.) folded back before commit.

## Two engagement modes

**1. Bug-bounty passive recon** (original) — ingest a program (`/program-load`), run the hunts, verify ownership, `/draft-report`. Passive-only; no light-active probing of program infra.

**2. Huella Digital** (`/domain <domain>`, added 2026-05-27) — client-work-project mode for an **external-attack-surface / digital-footprint** assessment of a single domain. Authorization = bare-domain-is-go. Synthesizes a `engagement_type:"huella_digital"` scope, runs the four hunts **plus `footprint-hunter`** (DNS surface w/ RFC1918 flagging, web-portal inventory + screenshots, IP reputation/RBL, emails/phones/social, **passive** breach listing), then **`huella-reporter`** assembles a Spanish **SYSCLOUDSEC "Informe de Huella Digital"** at `out/<slug>/reports/huella-digital-<ts>.md` scored on a Relevancia×Complejidad severity matrix.

Mode-2 boundaries (encoded as scope-rule flags): **light-active** tier ON (httpx homepage probe + 1 screenshot/host + DNSBL) but **credential validation HARD-OFF** (leaked creds listed only, `Estado=DESCONOCIDA`, never login-tested — requires separate written authorization), **heavy-active OFF** (no CVE/exploit), and the **LinkedIn-automation ban** stays (employee data via manual paste → §1.4.3). Breach source is pluggable (HIBP default, dehashed/credshed wireable). See `tools.md` → "Huella Digital mode".

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

## Learning loop & metrics (added 2026-06-07)

The pipeline's biggest blind spot was that it learned only from its own pre-submission
self-judgment — `platform_outcome` was `null` on every submission, so triager verdicts
never fed back. Four ingested dispositions (airtable N/A, toolsforhumanity + elastic
duplicate/low-impact, bc-chime accepted-but-duplicate) corrected more rules than a month
of self-graded retros. Tooling that closes and measures that loop:

- **`/stats`** (`scripts/bb_stats.py`) — funnel, per-engine yield, disposition tally,
  ownership verdicts, and rule-base health (filter:discovery ratio, confidence tiers,
  ground-truth-validated count). Read-only.
- **`/outcome <slug> <report-id|asset>`** (`scripts/bb_outcome.py`) — records a triager
  verdict into the audit trail, then fires a focused single-finding retro. This is the
  **one sanctioned path to a `high`-confidence rule** — disposition-grounded, not
  self-judged.
- **`/dup-check <slug> <asset>`** (`scripts/bb_duprisk.py`) — pre-submission
  duplicate-likelihood tier (3 of the first 4 dispositions were duplicates). Advisory;
  never hard-blocks. Wired into the `/draft-report` hand-off.
- **`scripts/bb_rule_audit.py`** — standing rule-base hygiene: flags self-judged-`high`
  rules (must carry a `grounding` field), missing provenance, dup IDs, stale refs to
  disabled rules, and filter:discovery drift.
- **`/route <slug>`** (`scripts/bb_route.py`) — pre-hunt engine-routing plan. Reads the
  target profile (GH org, wildcard count, web assets, caps) + actual historical per-engine
  yield and recommends RUN / DEPRIORITIZE / SKIP per hunt. Advisory; attacks the
  clean-negative streak by not spending budget on engines that don't pay off on a given
  target class (e.g. secret-hunter SKIP when there's no GH org; takeover-hunter SKIP on
  narrow scope / scanner ban). The prior sharpens as `/outcome` records more dispositions.

Rule confidence convention: `low`/`medium` are self-judged; `high` requires a `grounding`
field (`platform_disposition:<id>` or `user_policy`). Falsified rules are disabled
(`enabled:false` + `disabled_reason`), not deleted.

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
