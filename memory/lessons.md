# bb-agent lessons journal

Append-only narrative of what each engagement taught us. Read this at the start of a new program for context; act on the structured rules in `memory/rules.json`.

Each entry has the shape:

```
## <UTC date> — <program-slug>
**Proposal**: `memory/lessons/proposals/<ts>-<slug>.json`
**Applied rules**: <rule-id-1>, <rule-id-2>, ...

<2-5 paragraphs of what happened, what surprised us, what didn't work,
and any signal worth carrying into the next engagement.>
```

Entries are appended by `retro-analyzer` via `/retro apply`. The corresponding rules land in `memory/rules.json` with inline provenance so they can be traced back here.

---

<!-- Entries below this line, newest first -->

## 2026-05-14 — 8x8-bounty
**Proposal**: `memory/lessons/proposals/20260514-011248-8x8-bounty.json`
**Applied rules**: rule-secret_hunter-gh_org_override-52066, rule-ownership_verifier-bucket_aggregation_override-1c25c, rule-ownership_verifier-asset_pattern_overrides-37c51

First full pass against 8x8 (HackerOne, bug_bounty tier, requires_ownership_proof=true, automated_tools_allowed=false). 31 bucket candidates (Pass A only, hard-capped at 80 due to mass_scanning_allowed=false), 0 secret candidates (Pass A+B+C clean across jitsi org + 3 forks), 5 ownership checks recorded, all five resolved to `unknown`. Zero reports drafted.

**What worked.** The 2-of-3 ownership rule held the line across all five candidates: nothing was upgraded to `owned` despite three of them having GH `positive` on the surface. The wayback word-boundary rule from MELI carried over cleanly and zeroed-out hit-counts across 1500-3600 archived URLs per asset. The secret-hunter's slug-vs-org fallback to `jitsi` was the right call (Jitsi is in-scope source per the program), and the 100+-repo scan returning zero verified credentials is a useful prior for a mature OSS shop.

**What didn't.** Three systemic gaps surfaced. (1) GitHub substring degeneracy on Check A: `jitsi-files` came back A=positive with 84 hits, but manual triage showed every one of those was a substring inside `jitsi-filesharing-*` event names in Lua prosody plugins — zero word-boundary matches in actual source. GH's `q='"<asset>" in:file'` doesn't honor word boundaries. Same shape as the MELI wayback brand-stem issue but on the GitHub side, and v1 schema has no clean home for it without a snippet-fetch capability. (2) Bucket aggregation gap: `8x8-staging` came back A=neg, B=neg, C=inconclusive and got `unknown` rather than `unowned`. For buckets, C is structurally inconclusive (a CNAME chain never proves ownership absent a program-domain CNAME), so A+B both clean negative should land as `unowned`. (3) Slug-vs-org gap in secret-hunter: slug `8x8-bounty` is not a GH org. Step-2 dedupe with cap=1 corners into a 404 — the agent recovered via base-name fallback this time, but a per-slug override map would make it deterministic. (4) Pass A timeout: 8-min cap cut trufflehog mid-stream at ~100 repos in jitsi; not a hard problem but tunability would help.

**What surprised us.** All 31 buckets came back with public ACLs (`all_users_read=true` on 28 of 31, public-write on 2 of 31). At face value this looks like a goldmine; the verifier correctly resisted that pressure and kept every candidate at `unknown` absent a second positive signal. The generic stems `connect` and `jit` produced 13+ candidates between them but zero ownership signal — they're squatter-bait.

**Pre-flight for next visit.** Add `connect` and `jit` to `bucket_hunter.basename_skip` to short-circuit Pass A on those families. Hardcode `gh_org_override["8x8-bounty"] = ["jitsi", "8x8inc"]` so secret-hunter doesn't have to discover the org via fallback. If revisiting Jitsi for secrets, run Pass B+C only (the org has good hygiene). Reconsider how to express the GH-substring downgrade for Check A — v1.5 likely needs a snippet-fetch capability before this can be a rule rather than a narrative.

## 2026-05-14 — mercadolibre
**Proposal**: `memory/lessons/proposals/20260514-002318-mercadolibre.json`
**Applied rules**: rule-ownership_verifier-wayback_match_mode-879f3

First full pass against MercadoLibre (HackerOne, bug_bounty tier, requires_ownership_proof=true). 16 bucket candidates, 1 noseyparker-only secret candidate, 2 ownership checks recorded. Zero verified-owned assets, zero reports drafted.

**What worked.** The ownership-verifier did its job on the typo'd `mercadolivre` bucket: 3 clean negatives (0 GH hits, 0 wayback hits across 1037 archived URLs from 3 representative in-scope domains, generic AWS DNS) → verdict `unowned`. This is the historical waste-a-day asset from the README and the verifier correctly suppressed it.

**What didn't.** Two systemic issues. (1) Pass A trufflehog org scan on `mercadolibre` GH org (101 public repos, 63 enumerated, 514351 chunks / 2.7 GB, 2m25s) returned 0 verified hits — mature org, low yield-per-CPU. Future runs should weight Pass A lower for slugs like this. (2) Ownership-verifier wayback check on the bare brand-stem bucket `mercadolibre` returned 952 substring hits — every in-scope URL containing the brand name counts as a positive, which is a degenerate case. The 2-of-3 rule held the line (final verdict `unknown`, not `owned`), but the wayback signal is effectively useless when asset == brand stem.

**What surprised us.** The single noseyparker secret was the literal Odoo XML attribute `password="False"` — a boolean literal, not a credential. Generic Password detector is FP-prone on config templating languages.

**Pre-flight for next visit.** Skip bare-brand bucket basenames (or downweight them). Treat `Generic Password` detector hits on the literal token `False`/`True`/`None`/`null`/`undefined` as suppressed. Consider running Passes B+C only for MELI; reserve trufflehog org-scan budget for less-mature orgs. Wayback match mode should be `word_boundary` not `substring` to avoid the brand-stem degenerate-positive.
