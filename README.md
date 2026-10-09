# bb-agent — SYSCLOUDSEC offensive-security agent

Security-assessment workflows for Claude Code and Codex. Bug-bounty recon, web-application pentesting, cloud-configuration audits, and digital-footprint assessments — with a documentation axis (Eje 3) that packages findings into HackerOne markdown or SYSCLOUDSEC Typst reports.

**Codex:** open this repository in Codex and ask `Run stats`, `Run route <slug>`, or
name any workflow below in ordinary language. [AGENTS.md](AGENTS.md) loads the
existing playbooks and shared engagement memory. See [Codex setup and runtime
mapping](docs/codex.md) for tool dependencies and the internal-report coverage check.
Claude slash commands are workflow names in Codex, not registered UI commands.

**Built since 2026-05-11.** 30+ engagements, 60+ learned rules, 4 ground-truth-validated dispositions.

---

## Engagement modes

| # | Mode | Trigger | Deliverable |
|---|------|---------|-------------|
| 1 | **Bug-bounty passive recon** | `/program-load <url>` → hunts → `/draft-report` | HackerOne/Bugcrowd markdown |
| 2 | **Huella Digital** | `/domain <domain>` | SYSCLOUDSEC "Informe de Huella Digital" (Spanish) |
| 3 | **Active web-vuln** | `/auth-load` → `/webvuln-surface` → `/hunt-*` | Bounty markdown or SYSCLOUDSEC Typst |
| 4 | **Cloud audit** | `/audit-cloud <slug> <aws-profile>` | SYSCLOUDSEC Typst técnico |

### Mode 1 — Bug-bounty passive recon

Ingest a HackerOne/Bugcrowd/Intigriti program, run four passive hunters (secrets, buckets, takeovers, endpoints), verify ownership, draft reports. No active probing of program infrastructure.

### Mode 2 — Huella Digital

External-attack-surface assessment of a client domain. Synthesizes scope, runs the four hunts **plus `footprint-hunter`** (DNS surface, web portals + screenshots, IP reputation, emails/phones/social, passive breach listing). `huella-reporter` assembles the Spanish SYSCLOUDSEC report scored on a Relevancia×Complejidad severity matrix.

Boundaries: light-active tier ON (httpx probe + screenshot + DNSBL), credential validation HARD-OFF, heavy-active OFF, LinkedIn-automation ban (manual paste only).

### Mode 3 — Active web-vuln tier

Applicative vulnerability hunting via **Burp MCP** — IDOR/BOLA/BFLA, XSS, SQLi, SSRF/XXE, plus JWT/OAuth/GraphQL/race/biz-logic via `offensive-*` skills.

**Strict compliance gate** (`.claude/skills/webvuln-compliance/SKILL.md`):
- Hard gate: refuses if `automated_tools_allowed==false`, `explicit_scanner_ban==true`, target not in scope, or no safe-harbor
- Always off: DoS, brute force, destructive mutations, data exfil, attacking real users
- Proof ceiling: read ONE IDOR object, `alert(document.domain)` XSS, boolean/time SQLi (no dumps), OOB SSRF — confirm then stop

Pipeline: `/auth-load` → `/webvuln-surface` → `/hunt-access` (IDOR) → `/hunt-xss` → `/hunt-sqli` → `/hunt-ssrf` → `/verify-ownership` → `/draft-report`

### Mode 4 — Cloud configuration audit

Authenticated AWS read-only posture scan for contracted engagements. Operator provisions a `SecurityAudit + IAMReadOnlyAccess` role.

Runs: Prowler (CIS/PCI/NIST/SOC2), ScoutSuite, CloudFox, Cloudsplaining, PMapper (privesc→admin graph), IAM credential report, Access Analyzer, GuardDuty — then mandatory FP triage (policy conditions, SG→live-instance, cross-account attribution). Verified to kill ~44 S3 + ~71 SNS + ~43 SG false positives per account.

Boundaries: read-only, no writes, no privesc execution, no port scans, no GetObject. SSO tokens expire hourly → pauses and requests refresh.

---

## Documentation axis (Eje 3)

Two reporting channels, neither auto-submits:

| Channel | Command | Agent | Format |
|---------|---------|-------|--------|
| Bug-bounty | `/draft-report <slug>` | `report-drafter` | HackerOne/Bugcrowd markdown |
| SYSCLOUDSEC | `/informe <slug> <tecnico\|ejecutivo\|huella>` | `syscloud-reporter` | Typst (`@local/plantilla-syscloud`), compiled clean, staged for typst.app |

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │             ORCHESTRATOR                │
                    │  /program-load  /route  /stats          │
                    └──────────┬──────────────┬───────────────┘
                               │              │
              ┌────────────────┼──────────────┼────────────────┐
              │                │              │                │
     ┌────────▼──────┐ ┌──────▼───────┐ ┌────▼─────┐ ┌───────▼───────┐
     │ secret-hunter │ │bucket-hunter │ │ takeover │ │endpoint-hunter│
     │  trufflehog   │ │  s3scanner   │ │  hunter  │ │  gau+waymore  │
     │  noseyparker  │ │  cloud_enum  │ │ subfinder│ │  nuclei/httpx │
     │  gh-codesearch│ │              │ │   subzy  │ │               │
     └───────┬───────┘ └──────┬───────┘ └────┬─────┘ └───────┬───────┘
             │                │              │                │
             └────────────────┼──────────────┼────────────────┘
                              │              │
                    ┌─────────▼──────────────▼─────────┐
                    │      ownership-verifier           │
                    │  3-check: GH + Wayback + DNS      │
                    │  positive-proof model for buckets │
                    └──────────────┬────────────────────┘
                                   │
                    ┌──────────────▼────────────────────┐
                    │        report-drafter              │
                    │  hard-gated on verdict == owned    │
                    │  severity caps · no-inflation rule │
                    └──────────────┬────────────────────┘
                                   │
                    ┌──────────────▼────────────────────┐
                    │     HUMAN REVIEW & SUBMIT         │
                    └──────────────────────────────────┘

     ┌──────────────────────────────────────────────────────┐
     │              ACTIVE WEB-VULN TIER                    │
     │  webvuln-surface → access-control-hunter (IDOR)      │
     │                  → xss-hunter · sqli-hunter          │
     │                  → ssrf-hunter                       │
     │  All via Burp MCP · strict compliance gate (§1)      │
     │  Proof ceiling: confirm, don't exploit               │
     └──────────────────────────────────────────────────────┘

     ┌──────────────────────────────────────────────────────┐
     │              CLOUD AUDIT TIER                        │
     │  cloud-auditor: Prowler + ScoutSuite + CloudFox      │
     │  + PMapper + Cloudsplaining + IAM cred report        │
     │  + Access Analyzer + GuardDuty                       │
     │  → FP triage → FINDINGS.md → /informe tecnico       │
     └──────────────────────────────────────────────────────┘
```

---

## Subagents

| Agent | Purpose | Tools |
|-------|---------|-------|
| `program-scope-parser` | Ingest H1/BC/Intigriti program scope | WebFetch, Bash |
| `program-scout` | Find high-yield programs across platforms | WebFetch, Bash |
| `secret-hunter` | Leaked credentials (trufflehog + noseyparker + GH dorks) | Bash |
| `bucket-hunter` | Cloud storage enumeration (listing-only) | Bash |
| `takeover-hunter` | Subdomain takeover candidates (subfinder + subzy) | Bash |
| `endpoint-hunter` | Sensitive endpoints (gau + waymore + httpx + nuclei) | Bash |
| `footprint-hunter` | Digital-footprint OSINT (DNS, portals, reputation) | Bash |
| `ownership-verifier` | 3-check ownership chain + positive-proof model | Bash |
| `report-drafter` | Bug-bounty markdown (H1/BC format) | Read, Write |
| `syscloud-reporter` | SYSCLOUDSEC Typst deliverables (Eje 3) | Read, Write, Bash |
| `huella-reporter` | Spanish digital-footprint report assembly | Read, Write |
| `access-control-hunter` | IDOR / BOLA / BFLA / mass-assignment | Burp MCP |
| `xss-hunter` | Reflected / stored / DOM XSS | Burp + Playwright |
| `sqli-hunter` | Boolean, time-based, error-based SQLi | Burp MCP |
| `ssrf-hunter` | OOB callbacks, metadata, protocol handlers | Burp MCP |
| `webvuln-surface` | Testable injection-point inventory | Burp + Playwright |
| `auth-context` | Credential custody for authenticated testing | Burp MCP |
| `cloud-auditor` | AWS posture (Prowler + ScoutSuite + CloudFox + PMapper) | Bash |
| `retro-analyzer` | Post-engagement retrospective → rules + lessons | Read, Write |

---

## Slash commands

### Ingestion & routing
```
/program-load <url>          Ingest a H1/BC/Intigriti program
/find-programs               Scout high-yield programs
/route <slug>                Engine-routing recommendation (RUN/SKIP per hunt)
```

### Passive hunting
```
/hunt-secrets <slug>         Leaked credentials (trufflehog + noseyparker + GH dorks)
/hunt-buckets <slug>         Cloud bucket enumeration (S3/GCS/Azure)
/hunt-takeovers <slug>       Subdomain takeover candidates
/hunt-endpoints <slug>       Sensitive endpoint discovery
```

### Active web-vuln (requires Burp MCP)
```
/auth-load <slug>            Store + validate 1–2 test accounts
/webvuln-surface <slug>      Build injection-point inventory (no payloads)
/hunt-access <slug>          IDOR / BOLA / BFLA / mass-assignment
/hunt-xss <slug>             Cross-site scripting
/hunt-sqli <slug>            SQL injection
/hunt-ssrf <slug>            Server-side request forgery
```

### Verification & reporting
```
/verify-ownership <asset>    3-check ownership chain + positive-proof model
/draft-report <slug>         Bug-bounty markdown (gated on ownership == owned)
/informe <slug> <type>       SYSCLOUDSEC Typst deliverable (tecnico|ejecutivo|huella)
/domain <domain>             Digital-footprint assessment (Huella Digital)
/audit-cloud <slug> <prof>   AWS cloud-configuration audit
```

### Learning loop & metrics
```
/retro <slug>                Post-engagement retrospective → rule proposals
/outcome <slug> <id>         Record triager disposition (→ high-confidence rules)
/dup-check <slug> <asset>    Pre-submission duplicate-risk assessment
/stats                       Pipeline funnel, per-engine yield, disposition tally
/coverage-checklist <slug>   Internal-pentest coverage matrix (PTES/NIST/CIS/OWASP)
```

---

## Learning loop

```
Hunt → Verify → Draft → Submit → /outcome → /retro → rules.json
                                    ▲                      │
                                    │    confidence tiers   │
                                    │    low < medium < high│
                                    └──────────────────────┘
```

- **low/medium**: self-judged from engagement analysis
- **high**: grounded in external truth — triager verdict (`platform_disposition:<id>`) or explicit operator policy (`user_policy`)
- Falsified rules: disabled with `disabled_reason`, not deleted (cautionary records)
- Rule audit: `scripts/bb_rule_audit.py` flags self-judged-high, missing provenance, dup IDs, filter:discovery drift

**Key ground-truth lessons** (from 4 triager dispositions):
1. Bucket name derivation ≠ ownership (airtable N/A)
2. trufflehog Verified=true ≠ impact (elastic, toolsforhumanity duplicates)
3. Blockchain RPC keys are low-value by default (toolsforhumanity)
4. Detection-only takeover reports need demonstrated control on some platforms (bc-thetradedesk)
5. Valid findings DO get through when ownership and impact are real (bc-chime accepted)

---

## Directory layout

```
bb-agent/
├── .claude/
│   ├── agents/            31 subagent definitions
│   ├── commands/           36 slash commands
│   ├── skills/            Compliance gate (webvuln-compliance)
│   ├── hooks/             Coverage gate hook
│   └── settings.json      Project settings
├── memory/                (local only, gitignored — created by bootstrap.sh)
│   ├── programs/          Per-program scope JSON (<slug>.json)
│   ├── submissions/       Audit trail (drafted/submitted/dispositioned)
│   ├── ownership-cache/   Ownership verdicts (positive + negative, 30-day TTL)
│   ├── employee-cache/    Employee-discovery cache (Check A.5)
│   ├── rules.json         Learned rules with provenance
│   ├── lessons.md         Narrative journal (appended by /retro)
│   └── lessons/proposals/ Retro proposals (pending /retro apply)
├── scripts/               bootstrap, bb_route, bb_stats, bb_duprisk, bb_outcome, ...
├── tools.md               Tool inventory (install instructions, compliance flags)
├── out/                   Scan outputs + drafted reports (local only, gitignored)
└── SETUP.md               Installation and first-run guide
```

---

## Compliance rules

- No active mass scanning unless `automated_tools_allowed==true`
- One non-destructive validation call per finding source
- No bucket file downloads (`ListBucket` only, never `GetObject`)
- Ownership verification mandatory before any report is drafted
- 0-day age gate (>=30 days since CVE publication)
- Credentials stored off-repo with `chmod 0600`
- No auto-submit — every report requires human review
- Scanner bans detected at ingestion and enforced by all agents
- Proof ceiling on every active test class

---

## Quick start

```bash
git clone https://github.com/Kennyalfredo/bb-agent.git
cd bb-agent
bash scripts/bootstrap.sh   # creates memory/, out/, checks tools
claude                       # or open in Codex
```

```
# Scout programs
/find-programs

# Full passive recon
/program-load https://hackerone.com/target
/route target
/hunt-secrets target
/hunt-buckets target
/hunt-takeovers target
/hunt-endpoints target

# Active web-vuln (requires Burp MCP)
/auth-load target
/webvuln-surface target
/hunt-access target

# Post-engagement
/retro target
/stats
```

See [SETUP.md](SETUP.md) for full installation instructions.
