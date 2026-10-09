---
description: Enumerate subdomain-takeover candidates for an ingested program (passive subfinder + dnsx CNAME + subzy fingerprint, no claiming). Writes candidates to out/<slug>/takeovers/<ts>.json. Does NOT verify ownership.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are kicking off subdomain-takeover hunting for program slug: $ARGUMENTS

Delegate to the `takeover-hunter` subagent. Pass the slug and require it to:
1. Read `memory/programs/<slug>.json`. Cap model: the compliance-relevant cap is the **active-probe count** (subzy/curl/nuclei against program subdomains) → strict (`automated_tools_allowed=false`) 150 / default 500. Passive enumeration is **per-seed** (runtime only, no program contact) → strict 150/seed, default 500/seed. Seed cap strict 12 / default 25. See the agent's Hard-rules cap model.
2. Derive seed domains from in-scope wildcards/domains (strip leading `*.`). Cap at the seed cap; record dropped seeds in notes (wide-wildcard targets are where takeovers live — don't silently drop).
3. Run `subfinder`/`amass`/`crt.sh` per seed; aggregate and dedupe, applying the **per-seed** enumeration cap to each seed's bucket independently (not a single global cap — that was the flutteruki truncation).
4. Run `dnsx -cname -resp -silent -json` over the list; keep only subdomains with a non-empty CNAME chain.
5. Run `subzy run --targets <list> --output <out>.json --vuln --hide_fails --concurrency 20 --timeout 15` once.
6. Build candidates with `subdomain`, `cname[]`, `fingerprint_engine`, `subzy_status`, `in_scope_wildcard_match`. Write to `out/<slug>/takeovers/<UTC-ts>.json`.

When the subagent returns, give the user a tight summary:
- output file path
- the funnel: subdomains_enumerated → subdomains_with_cname → takeover_candidates
- top 3 candidates as `subdomain @ engine (cname)`
- the next command per candidate: `/verify-ownership <slug> <subdomain>`

Reminder to the user: detection is the report. **Do NOT register/claim the dangling endpoint to "prove" exploitation** — that's the takeover itself and out of scope. Subdomains under in-scope wildcards auto-satisfy ownership-verifier Check C via DNS-zone control; the `in_scope_subdomain_override` rule then promotes the verdict to `owned` without needing A or B positive, so the verifier should rarely return `unknown` on takeover candidates.
