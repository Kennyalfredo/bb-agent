---
description: Engine-routing plan for a program — reads the target profile (GH org, wildcard count, web assets, caps) + actual historical per-engine yield and recommends which hunts to RUN / DEPRIORITIZE / SKIP. Advisory; attacks the clean-negative streak by not spending budget on engines that don't pay off on this target class.
argument-hint: <slug> [--org-maturity young|mature|unknown] [--prior-run-cleanneg]
allowed-tools: Bash, Read
---

You are producing an engine-routing plan to consult BEFORE running the hunts on a program.

Arguments: $ARGUMENTS  (expected: `<slug>` plus optional flags)

## Step 1 — Judge the soft signals (the planner can't read these from JSON)

Before running the script, decide two things from what you know about the target:
- **org maturity** — is the program's GitHub org a large, polished, secret-scanning-mature org (the netflix/valve/opera/okg/dynatrace/basecamp cluster that returns test-fixture-only hits)? → `mature`. A younger/scrappier org? → `young`. Genuinely unsure? → `unknown`.
- **prior clean-neg** — has this exact slug already been run and come back clean-negative? Check `memory/lessons.md` for an entry. If yes, pass `--prior-run-cleanneg`.

## Step 2 — Run the planner

```
python3 scripts/bb_route.py <slug> [--org-maturity <young|mature|unknown>] [--prior-run-cleanneg]
```

It reads `memory/programs/<slug>.json` (the profile) and the recorded `platform_outcome` history (the per-engine yield prior), and emits RUN / DEPRIORITIZE / SKIP per engine with rationale.

## Step 3 — Relay + recommend an order

- Relay the plan verbatim.
- Give the operator a one-line **run order**: the RUN engines first, then RUN-low / DEPRIORITIZE if budget remains, and call out the SKIPs explicitly so a skip is a *decision*, not a silent omission.
- If an engine is SKIP only because of a policy cap (scanner ban) rather than low yield, say so — the cap may lift on a different program.

Reminders:
- **Advisory, never a hard gate.** The operator can run any engine; this just shows where the expected value is. A SKIP on takeover-hunter (0 accepted findings ever) is a strong default, but a genuinely novel wide-wildcard target can still justify a targeted pass.
- This reads only local state (program JSON + submissions). It touches no program infrastructure.
- The historical prior sharpens automatically as `/outcome` records more dispositions — re-run `/route` as the disposition data grows.
