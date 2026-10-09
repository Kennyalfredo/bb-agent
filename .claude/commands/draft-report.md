---
description: Draft a HackerOne/Bugcrowd-ready markdown report for a verified finding. Hard-refuses unless ownership cache says `verdict == owned`. With no asset arg → list-and-prompt mode. With an asset arg → draft mode. Writes report + appends audit trail; never auto-submits.
argument-hint: <program-slug> [asset]
allowed-tools: Agent
---

You are kicking off report drafting.
Arguments: $ARGUMENTS  (expected: `<slug>` for list-and-prompt mode, or `<slug> <asset>` for draft mode)

Delegate to the `report-drafter` subagent. Pass the arguments and require it to:
1. Read `memory/programs/<slug>.json`; refuse if missing.
2. If `<asset>` omitted: walk `out/<slug>/buckets/*.json` and `out/<slug>/secrets/*.json`, group candidates by their **verifiable asset** (bucket name OR secret's `repo_owner`), cross-reference each against `memory/ownership-cache/<sha1>.json` and `memory/submissions/<slug>.json`, then return three lists: **Draftable now / Needs ownership verification / Cannot draft** — and stop. No automatic pick.
3. If `<asset>` provided: hard-gate on `verdict == "owned"` AND `fetched_at` within 30 days. Refuse on `unknown` / `unowned` / stale / missing with a pointer to `/verify-ownership`. Refuse duplicate drafts within 30 days. Refuse noseyparker-only (unverified) secret candidates.
4. Compute severity = `min(proposed-by-class, scope.in_scope[*].severity_cap-for-asset)`.
5. Render the markdown using the bucket-exposure or leaked-secret template the agent doc defines.
6. Write the report to `out/<slug>/reports/<asset-slug>-<UTC-ts>.md` and append an audit-trail entry to `memory/submissions/<slug>.json` with `submitted: false`.

When the subagent returns:
- **List mode**: relay the three lists verbatim. End with "Reply `/draft-report <slug> <asset>` to draft one."
- **Draft mode**: relay the report path, final severity, audit-trail path, and the program's submission URL. Then prompt the operator to run **`/dup-check <slug> <asset>`** before submitting — 3 of the first 4 recorded dispositions were duplicates, and the pre-flight is cheapest to run now. End with: **"Do not auto-submit. Human edits + pastes; then sets `submitted: true` in `memory/submissions/<slug>.json`. Once a verdict comes back, run `/outcome <slug> <asset>` to close the loop."**

Reminders:
- This subagent NEVER touches the asset for fresh evidence (no curl, no nuclei, no httpx, no GH API).
- The subagent NEVER includes raw secret values — only the redacted prefix/suffix from the candidate JSON.
- The subagent NEVER submits. Output is markdown on disk for a human to paste.
