---
description: Eje 3 (Documentación) — render a SYSCLOUDSEC client deliverable in Typst. Delegates to syscloud-reporter to author one of the three report types (técnico/DAST-SAST, ejecutivo, huella digital) as a compile-clean `.typ` using the plantilla-syscloud package, validate it, and stage it for typst.app. Never auto-submits. This is the Typst channel; use /draft-report for bounty markdown.
argument-hint: <slug> <tipo>   (tipo = tecnico | ejecutivo | huella)
allowed-tools: Agent
---

You are kicking off a **SYSCLOUDSEC Typst deliverable** (Eje 3 — Documentación).
Arguments: $ARGUMENTS  (expected: `<slug> <tipo>`, tipo ∈ `tecnico|ejecutivo|huella`)

This is the **Typst channel** for client/owner engagements (SYSCLOUDSEC house style, per the standing instruction that every SYSCLOUDSEC deliverable is authored in Typst — not markdown). It is distinct from `/draft-report`, which produces single-finding HackerOne/Bugcrowd markdown for the bounty channel. Do not mix the two.

If `<tipo>` is missing or not one of `tecnico|ejecutivo|huella`, ask the operator to pick one (and state what each is: técnico = full per-finding CVSS+PoC+remediation; ejecutivo = plots + top-vuln tables, no CVSS/PoC; huella = external attack-surface footprint) before delegating.

Delegate to the `syscloud-reporter` subagent. Pass `<slug> <tipo>` and require it to:
1. Read `memory/programs/<slug>.json`; refuse if missing. Read the `report_drafter.auto_info_filter` no-local-paths rule (applies here too).
2. Gather content by tipo — `tecnico`/`ejecutivo` from the webvuln + hunt finding JSON (a técnico finding needs a real CVSS **vector**; never invent one); `huella` by transposing the latest `out/<slug>/reports/huella-digital-<ts>.md` (refuse if absent — run `huella-reporter`/`/domain` first).
3. Author `out/<slug>/reports/typst/<tipo>.typ` with `#import "@local/plantilla-syscloud:0.3.0": *`, obeying the house skeleton + every Typst gotcha (bold `*x*`, escape `\#`, plot amount order Crít→Info). Stage Carlito fonts + brand assets into `assets/` and evidence into `evidencias/` next to it. Never copy `plantilla-syscloud.typ` in.
4. Validate: `typst compile --font-path assets <tipo>.typ` must produce a PDF with **zero errors** (fix + recompile until clean).
5. Scrub all local paths from the body. Never auto-submit.

When the subagent returns, relay: the `.typ` path, the compiled PDF path, per-severity counts, whether the compile was clean, and the typst.app upload steps (syscloud team → upload `.typ` at root + `assets/` folder → "Set as preview"; stage under `~/bb-agent/.playwright-mcp/` for the sandboxed Playwright upload). End with: **"Compile is clean and staged — but nothing is delivered. The human reviews, uploads to typst.app, and sends it to the client."**

Reminders:
- syscloud-reporter NEVER collects fresh data or touches an asset.
- It NEVER invents a CVSS vector — no vector → minor-findings summary table with a manual severity label.
- It NEVER submits, emails, or uploads. Output is a compile-clean `.typ` on disk for a human to deliver.
