---
description: Build the testable request surface (endpoints, params, forms, JSON bodies, reflected inputs, object-ref seeds) for the active web-vuln tier. Merges the passive gau/endpoint corpus + Burp history with a light authenticated Playwright crawl. No payloads — discovery only. Output feeds the class hunters.
argument-hint: <program-slug>
allowed-tools: Agent
---

You are building the active-testing surface for program slug: $ARGUMENTS

Delegate to the `webvuln-surface` subagent. Require it to:
1. Read `.claude/skills/webvuln-compliance/SKILL.md` + `memory/programs/<slug>.json`; apply the §1 hard gate (REFUSE on `automated_tools_allowed==false` / `explicit_scanner_ban==true`) and write an empty-surface output with `refused_reason` if it fires.
2. Seed for free from the newest `out/<slug>/endpoints/*.json` gau corpus + in-scope Burp proxy history (params/bodies that already exist — no live requests).
3. Run a light authenticated Playwright crawl of in-scope hosts (attach the auth-context if present), capturing forms + XHR/fetch API endpoints + JSON body shapes. Benign values only; in-scope hosts only; honor the rate cap; respect the page/endpoint caps.
4. Normalize to injection points, tagging `looks_numeric_id`/`looks_uuid` (IDOR seeds) and `reflected` (injection seeds) and redirect-ish params (SSRF/open-redirect seeds).
5. Write `out/<slug>/webvuln/surface/<UTC-ts>.json`.

When the subagent returns, relay:
- the funnel: `passive_seed_urls + crawl_pages → endpoints → injection_points → {idor / reflection / redirect} seeds`,
- whether the crawl ran authenticated (richer) or anonymous,
- top in-scope hosts by injection-point count,
- the literal next step: `/hunt-access <slug>` (IDOR/BOLA/BFLA) — and a note that injection/ssrf/auth-api hunters consume the same surface as they come online.

Reminder to the user: this step sends NO payloads — it only discovers inputs. If the gate refused, the active tier is off for this program (e.g. MELI: `automated_tools_allowed=false`) and the passive tier is the path instead.
