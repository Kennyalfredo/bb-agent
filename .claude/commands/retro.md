---
description: Post-engagement retrospective. `/retro <slug>` analyzes engagement artifacts and proposes lesson rules (writes proposal file only). `/retro apply <proposal-id> [rule-ids...]` commits selected rules to memory/rules.json and appends the narrative to memory/lessons.md. Never auto-applies.
argument-hint: <program-slug> | apply <proposal-id> [rule-id-1 rule-id-2 ...]
allowed-tools: Agent
---

You are kicking off retro analysis or apply.
Arguments: $ARGUMENTS  (expected: `<slug>` for analyze mode, or `apply <proposal-id> [rule-ids...]` for apply mode)

Delegate to the `retro-analyzer` subagent. Pass the arguments verbatim.

**Analyze mode** (first arg is a program slug): require the agent to
1. Read `memory/programs/<slug>.json`; refuse if missing.
2. Walk `out/<slug>/(buckets|secrets|reports)/*`, `memory/ownership-cache/*.json` filtered by slug, and `memory/submissions/<slug>.json` if present.
3. Compute aggregate metrics; run the heuristics documented in the agent doc (H1 noseyparker FPs, H2 brand-stem Wayback degeneracy, H3 mature-org pass-A signal, H4 bare-brand bucket inconclusive, H5 platform-dismissed reports).
4. Compose a narrative entry (2-5 paragraphs) and the proposed rules (≤5).
5. Write the proposal to `memory/lessons/proposals/<UTC-ts>-<slug>.json` with rule IDs of the form `rule-<agent>-<path>-<5-char-hash>`.

**Apply mode** (first arg is the literal `apply`): require the agent to
1. Read `memory/lessons/proposals/<proposal-id>.json`; refuse if missing.
2. Filter rules by the human-supplied allowlist (or apply all if none given).
3. For each rule: append to the relevant array in `memory/rules.json`, or set a scalar if it's still at the schema default. Refuse to overwrite an existing non-default scalar (tell the human to use `/forget` when that command exists).
4. Stamp every applied rule with `id / added / from_engagement / confidence / reason` provenance.
5. Append the proposal's narrative to `memory/lessons.md` right after the marker comment.

When the subagent returns:
- **Analyze**: relay the proposal file path, the metric one-liner, and every proposed rule with its `rule_id` and 1-line rationale. End with the exact `/retro apply` commands (apply-all + apply-selective).
- **Apply**: relay how many rules landed vs skipped vs refused, plus the rule IDs that committed. End with: "Future runs of the affected agents pick up these rules automatically at their step 0."

Reminders:
- Analyze NEVER mutates `rules.json` or `lessons.md`. Only apply does, and only on the rule IDs the human passes (or all, if explicitly invoked with no allowlist).
- v1 confidence ceiling is `medium`. `high` requires cross-engagement corroboration (lands in v1.5).
- Refuse to propose more than 5 rules per engagement — narrative the rest.
