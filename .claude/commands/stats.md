---
description: Pipeline metrics rollup — funnel (programs→engagements→drafts→submissions→dispositions), per-engine yield, disposition tally, ownership-cache verdicts, and rule-base health (filter-vs-discovery ratio, confidence tiers, ground-truth-validated count). Read-only.
argument-hint: [--json]
allowed-tools: Bash
---

You are producing the bb-agent metrics rollup.

Run the deterministic aggregator:

```
python3 scripts/bb_stats.py $ARGUMENTS
```

(`--json` for machine-readable; no args for the human-readable table.)

Then relay its output to the user, and add a short **read** beneath it (2–4 lines) calling out anything notable in THIS run's numbers, for example:
- the submitted→disposition gap (how many outcomes are still unrecorded — these are blind spots; `/outcome` closes them)
- the **filter-to-discovery rule ratio** (drift watch — a high ratio means the learning loop is mostly pruning, not finding; see [[feedback-discovery-vs-filter-bias]])
- any engine with submissions but **zero** accepted-or-valid (candidate for engine-routing review)
- ground-truth-validated rule count vs total (how much of the rule base is backed by real triager verdicts vs self-judgment)

Do NOT mutate anything — this command only reads. If the script errors (missing file, malformed JSON), report the error verbatim and the path it choked on; do not paper over it with estimates.
