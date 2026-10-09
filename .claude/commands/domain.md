---
description: Digital-footprint ("Huella Digital") engagement on a bare domain — synthesizes scope, runs the full passive pipeline PLUS footprint OSINT (DNS surface, web portals + screenshots, IP reputation, emails/phones/social, passive breach listing), and assembles a Spanish SYSCLOUDSEC "Informe de Huella Digital". Authorized footprinting (light-active tier), NOT credential validation.
argument-hint: <domain>  (e.g. example.com)
allowed-tools: Agent, Bash, Write, Read, AskUserQuestion
---

You are running a **Huella Digital** (external-attack-surface) engagement for the domain: $ARGUMENTS

This is the client-work-project mode (distinct from the bug-bounty passive-only mode). Authorization model: **bare domain = go** (the user supplying the domain is the authorization, same as any directed bare-domain run). The engagement stays in the **light-active tier**: DNS + archive + OSINT passive collection, plus httpx homepage probing + web screenshots + DNSBL lookups. It does NOT validate credentials, attempt logins, scrape LinkedIn, or run CVE/exploit templates.

## Orchestration

### 1. Derive slug + synthesize scope JSON
- `domain` = $ARGUMENTS (lowercase, strip scheme/path/trailing dot).
- `slug` = leftmost label of the registrable domain (`example.com` → `example`). If `memory/programs/<slug>.json` already exists for a DIFFERENT domain, fall back to dots→dashes (`example.com` → `example-com`). Confirm the chosen slug back to the user in your first message.
- Write `memory/programs/<slug>.json` (reuse the synthesized-scope shape) with:
  - `program`: `{slug, platform:"direct", name:"<domain> (Huella Digital — owner/authorized)", url:"https://<domain>", fetched_at:<today>, engagement_type:"huella_digital"}`
  - `scope.in_scope`: apex `{type:"domain", asset:"<domain>", severity_cap:"high"}` + wildcard `{type:"wildcard", asset:"*.<domain>"}`
  - `rules`: `mass_scanning_allowed:false`, `bucket_listing_allowed:true`, `bucket_download_allowed:false`, `automated_tools_allowed:true`, `light_active_allowed:true`, `screenshots_allowed:true`, `social_enum_allowed:true`, `credential_validation_allowed:false`, `heavy_active_allowed:false`, `cve_age_min_days:30`, `requires_ownership_proof:true`, `safe_harbor:true`, `rate_limit_cap_rps:5`, plus a `notes` line recording the Huella-Digital basis + date.
  - `engagement_type:"huella_digital"` at top level too (some agents check both places).

### 2. Baseline
Run a quick inline DNS/whois baseline (A/NS/MX/TXT + registrar/creation) like the directed runs, and report what the stack looks like (host/registrar/mail).

### 3. Launch collection IN PARALLEL (single message, multiple Agent calls)
- `footprint-hunter` — slug; the NEW OSINT collection (DNS surface, web portals + screenshots, reputation, emails/phones/social, passive breach listing). Remind it: credential_validation is OFF, LinkedIn ban absolute, light-active ceiling. Social discovery = footer-scrape of client pages (official profiles) + maigret brand-handle enum across third-party platforms (anonymous public-URL checks, gated on `social_enum_allowed`) — flag any brand-handle profile NOT linked from the client site as a possible impersonation/squatting lead.
- `secret-hunter` — slug (existing pipeline).
- `bucket-hunter` — slug.
- `takeover-hunter` — slug (its DNS enum also feeds footprint-hunter's surface table; footprint-hunter may reuse its output).
- `endpoint-hunter` — slug. Note `automated_tools_allowed:true` here means its active live-probe runs (light-active tier) — that's intended for /domain, rate-limited at 5 rps.

### 4. Manual LinkedIn step (per the locked decision — manual-only)
After collection, use AskUserQuestion (or a plain prompt) to offer: paste LinkedIn employee data (Nombre — Cargo, Ubicación lines) for §1.4.3, or skip. If provided, write it to `out/<slug>/footprint/linkedin-manual.json` as `{ "company_url": "...", "employees": [{"name":"...","role":"...","location":"..."}] }`. If skipped, write `{ "employees": [], "skipped": true }`.

### 5. Assemble the report
Call `huella-reporter` — slug. It reads the footprint output + the four hunt outputs + the LinkedIn paste + ownership cache, applies the severity matrix, and writes `out/<slug>/reports/huella-digital-<ts>.md` (Spanish, SYSCLOUDSEC-branded). Copy any login-portal screenshots into `out/<slug>/reports/screenshots/` so the report's relative image links resolve.

**This markdown is the classified intermediate, not the client deliverable.** The SYSCLOUDSEC-facing artifact is authored in Typst (standing instruction — every SYSCLOUDSEC deliverable is Typst, not markdown). After huella-reporter finishes, the operator produces the final deliverable with **`/informe <slug> huella`** (Eje 3 — Documentación), which transposes this classified markdown into the `huella-digital.typ` skeleton, compiles it clean, and stages it for typst.app.

### 6. Summarize to the user
Report: chosen slug + scope path; baseline stack; per-section collection counts (subdomains/private-IPs, web hosts/login portals/non-standard ports, emails, phones, social [official footer / maigret candidates / impersonation leads], breach accounts + provider, reputation); any findings folded in from the hunts (takeover, exposed endpoints, attributable secrets); the report path; and the overall posture rating. Point the operator to **`/informe <slug> huella`** for the final Typst deliverable. State plainly that **credential validation + access PoC were NOT performed (passive list only) and require written client authorization**, and that **LinkedIn data was manual-only**.

## Guardrails (state these hold)
- Light-active ceiling: against the CLIENT's infrastructure only DNS, single httpx homepage probe, one screenshot per host, DNSBL queries, and a one-shot homepage GET for footer social-link extraction. No login attempts, no credential reuse, no nuclei CVE/exploit, no LinkedIn scraping, no port sweeps.
- Social handle-enum (maigret, `social_enum_allowed:true`) is the one step that contacts THIRD-PARTY platforms — anonymous public-URL existence checks only (no auth, no API keys, no content scraping), LinkedIn excluded. Set `social_enum_allowed:false` to keep the run client-only.
- `credential_validation_allowed` and `heavy_active_allowed` stay `false`. Do not flip them in this command.
- After the run, the scope JSON's active flags can remain (this mode is inherently light-active) — but never enable credential validation.
- Honor the no-local-paths rule in the delivered report.
