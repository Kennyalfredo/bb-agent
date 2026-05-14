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

## 2026-05-14 — mercadolibre
**Proposal**: `memory/lessons/proposals/20260514-002318-mercadolibre.json`
**Applied rules**: rule-ownership_verifier-wayback_match_mode-879f3

First full pass against MercadoLibre (HackerOne, bug_bounty tier, requires_ownership_proof=true). 16 bucket candidates, 1 noseyparker-only secret candidate, 2 ownership checks recorded. Zero verified-owned assets, zero reports drafted.

**What worked.** The ownership-verifier did its job on the typo'd `mercadolivre` bucket: 3 clean negatives (0 GH hits, 0 wayback hits across 1037 archived URLs from 3 representative in-scope domains, generic AWS DNS) → verdict `unowned`. This is the historical waste-a-day asset from the README and the verifier correctly suppressed it.

**What didn't.** Two systemic issues. (1) Pass A trufflehog org scan on `mercadolibre` GH org (101 public repos, 63 enumerated, 514351 chunks / 2.7 GB, 2m25s) returned 0 verified hits — mature org, low yield-per-CPU. Future runs should weight Pass A lower for slugs like this. (2) Ownership-verifier wayback check on the bare brand-stem bucket `mercadolibre` returned 952 substring hits — every in-scope URL containing the brand name counts as a positive, which is a degenerate case. The 2-of-3 rule held the line (final verdict `unknown`, not `owned`), but the wayback signal is effectively useless when asset == brand stem.

**What surprised us.** The single noseyparker secret was the literal Odoo XML attribute `password="False"` — a boolean literal, not a credential. Generic Password detector is FP-prone on config templating languages.

**Pre-flight for next visit.** Skip bare-brand bucket basenames (or downweight them). Treat `Generic Password` detector hits on the literal token `False`/`True`/`None`/`null`/`undefined` as suppressed. Consider running Passes B+C only for MELI; reserve trufflehog org-scan budget for less-mature orgs. Wayback match mode should be `word_boundary` not `substring` to avoid the brand-stem degenerate-positive.
