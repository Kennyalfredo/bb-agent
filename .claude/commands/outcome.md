---
description: Ingest a platform disposition (triager verdict) into the audit trail and learn from it. Records platform_outcome into memory/submissions/<slug>.json, then runs a focused single-finding retro that proposes ground-truth-grounded rules. Closes the disposition-feedback loop.
argument-hint: <slug> <report-id-or-asset>  (paste the triager's verdict text in the same message)
allowed-tools: Bash, Agent, Read
---

You are ingesting a platform disposition (a triager's verdict on a submitted report) and turning it into a learned rule. This is the disposition-feedback loop — the single most valuable signal the pipeline gets, because it is ground truth rather than self-judgment.

Arguments: $ARGUMENTS  (expected: `<slug> <report-id>` or `<slug> <asset>`)

The user has pasted the triager's verdict in the conversation (the close reason, status change, reward, duplicate-of reference, etc.). If they have NOT, ask them to paste it before proceeding — do not invent a disposition.

## Step 1 — Extract the disposition fields from the pasted verdict

Build a `platform_outcome` JSON object. Required: `disposition`, `captured_at` (today's date YYYY-MM-DD), `lesson`. Include every other field the verdict provides:

- `disposition` — normalize to one of: `resolved`, `rewarded`, `triaged`, `duplicate`, `informative`, `not_applicable`, `out_of_scope`, `spam`, `withdrawn`, `needs_more_info`.
- `validity` — if the platform accepted the finding as real but closed it duplicate, set `"ACCEPTED_AS_VALID_ISSUE"` (Bugcrowd phrasing). This distinguishes a *correct-but-duplicated* finding from a *wrong* one — they teach opposite lessons.
- `duplicate_of`, `original_disposition` (e.g. dup-of-an-informative), `closed_by`, `closed_at`, `reward_usd`.
- `triager_reason_verbatim` — the triager's exact words. Strongly preferred; it's the highest-signal artifact.
- `lesson` — 2–4 sentences: what the loop should learn. Be specific about the ROOT CAUSE (ownership-inference? impact-inflation? verified≠impact? duplicate-risk?). Link related memories with `[[name]]`.

## Step 2 — Write it (deterministic)

```
python3 scripts/bb_outcome.py --slug <slug> (--report-id <id> | --asset <asset>) --outcome-json '<the object>'
```

The script refuses to clobber an existing `platform_outcome` (pass `--force` only if the user explicitly wants to overwrite). If it errors on no-match, relay the entry list it printed and ask the user to disambiguate with `--asset`.

## Step 3 — Focused retro (the learning)

Delegate to the `retro-analyzer` subagent in **outcome mode**: pass the slug, the report-id/asset, and the full `platform_outcome` object. Require it to:
1. Read `memory/submissions/<slug>.json` (the entry you just wrote) and `memory/programs/<slug>.json`.
2. Propose **≤2** rules grounded SOLELY in this disposition — not a full engagement retro.
3. A rule grounded in a real triager verdict MAY carry `confidence: high` (it exceeds the self-judged `medium` ceiling — this is the one sanctioned path to `high`). A rule that REVOKES or DISABLES an existing rule the disposition falsified is in-scope and encouraged.
4. Write the proposal to `memory/lessons/proposals/<UTC-ts>-<slug>-outcome.json`. Do NOT auto-apply.

## Step 4 — Relay

- Confirm the outcome was recorded (slug / asset / disposition / new submission_state).
- Surface the proposed rule(s) with their IDs and 1-line rationale.
- End with the exact `/retro apply <proposal-id> [rule-ids...]` command, and remind: nothing is committed to `rules.json` until the human runs apply.

Reminders:
- Never fabricate a disposition or a verbatim reason. If the user's paste is ambiguous, ask.
- `validity: ACCEPTED_AS_VALID_ISSUE` + `duplicate` ⇒ the finding was CORRECT; the lesson is about duplicate-risk, NOT about the finding being wrong. Don't let an accepted-but-duplicate verdict spawn a suppression rule for a valid technique.
- After this, `/stats` will show one more disposition recorded and one fewer pending.
