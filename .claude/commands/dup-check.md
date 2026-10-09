---
description: Pre-submission duplicate-risk pre-flight for a drafted finding. Gathers passive signals (exposure age, archive indexing, asset prominence, finding class, public disclosures) and scores a duplicate-likelihood tier (LOW/MEDIUM/HIGH/NEAR-CERTAIN). Advisory only — never hard-blocks. 3 of the first 4 dispositions were duplicates.
argument-hint: <slug> <asset>
allowed-tools: Bash, Read, WebSearch
---

You are running a duplicate-risk pre-flight on a drafted finding before the human submits it.

Arguments: $ARGUMENTS  (expected: `<slug> <asset>`)

## Step 1 — Gather signals (passive)

1. Locate the candidate that backs this asset under `out/<slug>/(secrets|buckets|endpoints|takeovers)/*.json`. Read it.
2. Derive each signal:
   - **exposure_age_days** — for secrets: days since `first_seen` / first-commit date. For endpoints/services: days since the earliest Wayback/archive snapshot. For buckets: best estimate or omit if unknown.
   - **archive_indexed** — set if the EXACT finding artifact (the secret-bearing file URL, the service URL, the one-time-secret URL) appears in Wayback/gau/CommonCrawl evidence in the candidate JSON.
   - **asset_prominence** — `high` if a flagship/popular repo or the program's primary brand domain; `medium` for a normal product asset; `low` for an obscure/internal one.
   - **finding_class** — `oss_default_exposure` (a publicly-running open-source tool at default config), `well_known_repo_secret` (secret in a flagship/popular repo everyone scans), `common_misconfig` (listable bucket, default creds), or `novel`.
   - **test_or_history_path** — set if the secret is in a test/CI fixture path or is git-history-only.
3. **Optional public-disclosure check** — search public, already-disclosed reports for this program for the same asset/class (HackerOne Hacktivity, Bugcrowd CrowdStream disclosed reports). This reads only public disclosure pages — it does NOT touch program infrastructure. Count hits that reference the same asset or the same finding class. If you cannot/decline to search, pass `--public-disclosure-hits 0` and say so.

## Step 2 — Score (deterministic)

```
python3 scripts/bb_duprisk.py \
  --exposure-age-days <n> [--archive-indexed] \
  --asset-prominence <high|medium|low> \
  --finding-class <oss_default_exposure|well_known_repo_secret|common_misconfig|novel> \
  --public-disclosure-hits <n> [--test-or-history-path]
```

(Omit `--exposure-age-days` if genuinely unknown rather than guessing.)

## Step 3 — Relay + record

- Report the tier, score, and the contributing factors verbatim from the scorer.
- Give the operator a one-line recommendation tuned to the tier (submit / submit-but-don't-over-invest / skip).
- If a `memory/submissions/<slug>.json` entry already exists for this asset, note that the tier can be added to its audit-trail entry as `duplicate_risk: {tier, score, checked_at}` (offer to write it; don't auto-write).

Reminders:
- This is **advisory**. We cannot see private reports, so duplicate-risk is partly unavoidable — never present the tier as a reason a valid finding is worthless. A NEAR-CERTAIN tier on an `ACCEPTED_AS_VALID_ISSUE`-class technique still means "submit if it pays duplicate points or differentiates," not "don't submit."
- Reads public disclosure pages only. No requests to the program's own infrastructure.
