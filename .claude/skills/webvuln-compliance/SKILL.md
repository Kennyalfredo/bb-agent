---
name: webvuln-compliance
description: Shared compliance gate + proof-only rules for bb-agent's ACTIVE web-vulnerability tier. Every active hunter (access-control-hunter, sqli-hunter, xss-hunter, ssrf-hunter, injection-hunter, ssrf-xxe-hunter, auth-api-hunter) reads this at Step 0 and re-checks before every active request. Defines the strict per-program gate, the always-off list, throttling, and the "confirm-don't-exploit" proof ceiling that keeps the active tier inside bug-bounty rules.
---

# webvuln-compliance — the active-testing gate

bb-agent's original tier is **passive recon** (buckets, secrets, takeover, endpoint
disclosure). This skill governs the **active web-vulnerability tier** — the hunters that
send real payloads (XSS, SQLi, SSRF, IDOR, JWT, …) to in-scope targets via the Burp MCP.

Active testing has a different risk profile than passive recon. These rules are the
guardrails that keep it authorized. **Every active hunter embeds the hard gate (§1) inline
at its Step 0 and re-reads the program flags before each active step.** This skill is the
canonical reference; if an agent doc and this skill disagree, the stricter wins.

---

## §1 — The hard gate (REFUSE and stop if any fails)

Read `memory/programs/<slug>.json` → `rules`. Refuse to run the active tier (write an
empty-candidates output with `refused_reason`, report back, stop) when **any** of:

| Condition | Why |
|---|---|
| `rules.automated_tools_allowed == false` | Program forbids automated/active tooling. **This is the MELI case** — active tier does NOT run; the passive tier still does. |
| `rules.explicit_scanner_ban == true` | Same hard semantics as `rule-takeover_hunter-refuse_if_explicit_scanner_ban-739e9`. |
| target host is **not** under an `scope.in_scope[*]` wildcard/domain | Never send an active payload to anything not provably in scope. |
| `rules.safe_harbor == false` AND no explicit per-engagement operator go | No legal safe-harbor → don't act without a human decision. |

The gate is re-evaluated before EVERY active step, in case rules were edited mid-run.

> A program that bans *mass automated scanning* but `automated_tools_allowed` is true (or
> the parser left it unset and the policy invites "creative testing") still passes the gate
> — but runs under the **low-volume** posture in §3, not scanner-speed. When a policy says
> "no mass scanning, creative testing encouraged" AND the parser set `automated_tools_allowed=false`,
> the hard gate wins and the active tier refuses. Lifting that requires the operator to
> flip the flag deliberately (the future "creative-manual" mode), never the agent.

---

## §2 — Always off (regardless of program flags)

These are never performed by any active hunter, even on a program that allows automated tools:

- **DoS / load**: no flooding, no concurrency storms, no resource-exhaustion payloads (no billion-laughs XXE, no ReDoS, no GraphQL depth-bombs as *DoS* — see §4 for the read-only exception).
- **Brute force**: no credential/2FA/token brute-forcing for rate-limit discovery.
- **Mass account creation**, **spam**, **social engineering / phishing**, **physical**, **malware delivery**.
- **Destructive mutations**: no `DROP`/`DELETE`/`UPDATE`/`INSERT` via SQLi; no state-changing IDOR writes against another user's object; no `rm`/file-write via command injection.
- **Data exfiltration beyond proof**: confirm existence/impact with the *minimum* evidence, then stop. Never bulk-dump a database, never enumerate every object in an IDOR range, never read another user's full PII set.
- **Attacking other users**: no cookie theft from real users, no stored-XSS that fires on anyone but your own test account.

---

## §3 — Throttle & posture

- Honor `rules.rate_limit_cap_rps` verbatim. If unset, default **2 req/s** for the active tier (deliberately below the passive tier's 5 — active payloads are higher-touch).
- Prefer **single-request proofs**. A reflected-XSS proof is one request; a time-based SQLi proof is a small handful (baseline + 2 timed), not a sqlmap run.
- Use **your own test accounts** (`auth-context`), test users, and test cards where the program provides them (e.g. MELI's developer test users — though MELI's active tier is gated off).
- Tag every active request sent through Burp so it's auditable (note in evidence dir).

---

## §4 — The proof ceiling ("confirm, don't exploit")

This mirrors the passive tier's *"detection is the report."* For each class, the **maximum**
allowed action to confirm — go no further:

| Class | Proof ceiling (STOP here) | Forbidden |
|---|---|---|
| **IDOR / BOLA** | Read **one** adjacent object you shouldn't see; capture the differing field as evidence. | Enumerating the ID range; harvesting other users' data. |
| **BFLA / access control** | Reach the privileged function once and observe the authorized-only response shape. | Performing the privileged *action* (delete, payout, role-grant). |
| **Reflected/DOM XSS** | See **§4b — XSS proof ceiling by engagement type** below. | Stored XSS that executes for real users; cookie exfil to external host; session hijacking. |
| **SQLi** | See **§4a — SQLi proof ceiling by engagement type** below. | Any write (`INSERT`/`UPDATE`/`DELETE`/`DROP`); OS command exec; sensitive file reads (`/etc/shadow`); bulk data extraction. |
| **SSTI** | Arithmetic eval proof (`{{7*7}}`→`49`) and engine identification. | OS command exec / file read beyond a single innocuous proof. |
| **SSRF** | See **§4c — SSRF proof ceiling by engagement type** below. | Pivoting to internal services for exploitation; extracting live IAM/cloud credentials; sensitive file reads; port scanning beyond 5 probes; SSRF→RCE chains. |
| **XXE** | OOB callback to Collaborator OR a single innocuous local-file read proof (`/etc/hostname`-class), capped. | `/etc/shadow`, large-file reads, internal port-scanning. |
| **JWT / OAuth** | Forge a token that the app *accepts* for **your** account, or demonstrate the redirect/leak with a benign sink. | Taking over another user's account/session. |
| **Race / business logic** | The minimum concurrent requests to show the limit breaks (e.g. 2× redemption). | Repeating for material gain; financial harm. |

### §4a — SQLi proof ceiling by engagement type

The SQLi proof ceiling adapts to the engagement's authorization level. Read
`engagement_type` (or `tier`) from `memory/programs/<slug>.json`:

| Engagement type | Proof ceiling (STOP here) | sqlmap flags allowed | Candidate cap |
|---|---|---|---|
| **`bug_bounty`** | Boolean-diff OR time-delay (`SLEEP(5)` Δ ≥ 4s) OR `version()`/`current-db` read. No schema enumeration. | `--banner --current-db --level=1 --risk=1` (confirmed) or `--level=2 --risk=1` (high_suspicion). NEVER `--dump`/`--tables`/`--os-shell`. | 80 default / 20 strict |
| **`contracted_pentest`** | Everything in bug_bounty PLUS: schema enumeration (`--tables --columns`), innocuous file read (`/etc/hostname` class), user enumeration on own test DB. Still NO data dump (`--dump`), NO OS command exec, NO sensitive file reads. | `--banner --current-db --tables --columns --level=3 --risk=2`. Still NEVER `--dump`/`--dump-all`/`--os-shell`/`--os-pwn`/`--file-write`. `--file-read=/etc/hostname` only. | 120 default / 40 strict |
| **`huella_digital`** | SQLi hunting does NOT apply — huella is passive external footprint only. The §1 gate should refuse, but if it doesn't, the sqli-hunter must refuse with `refused_reason: "huella_digital engagement — active SQLi testing not authorized"`. | N/A | N/A |

The engagement type also affects the **suspicion scoring thresholds**:

| Engagement type | confirmed threshold | high_suspicion range | sqlmap on high_suspicion |
|---|---|---|---|
| `bug_bounty` | ≥ 75 | 50–74 | `--technique=BEUT --level=2 --risk=1` |
| `contracted_pentest` | ≥ 65 (lower bar — client authorized deeper testing) | 40–64 | `--technique=BEUST --level=3 --risk=2` |

### §4b — XSS proof ceiling by engagement type

The XSS proof ceiling adapts to the engagement's authorization level. Read
`engagement_type` (or `tier`) from `memory/programs/<slug>.json`:

| Engagement type | Proof ceiling (STOP here) | Stored/Blind XSS | Candidate cap |
|---|---|---|---|
| **`bug_bounty`** | `alert(document.domain)` or equivalent (`confirm`, `console.log`) firing in **your own** browser/session. For reflected: one-request PoC URL. CSP-mitigated reflection = still a finding but severity `low`. | Stored XSS only in **your own** test account fields (display name, bio, comment on your own content). Blind XSS NOT recommended (Collaborator callbacks may trip program rules). | 80 default / 20 strict |
| **`contracted_pentest`** | Everything in bug_bounty PLUS: stored XSS across test accounts, blind XSS with Collaborator callback (capturing YOUR OWN data only), DOM XSS with full source-to-sink trace, impact demonstration (show what an attacker could do — session token capture in YOUR session, but don't exfiltrate to external server). | Stored XSS in broader input fields (support tickets, feedback, admin-visible logs). Blind XSS with Collaborator callback enabled. Clean up all injected payloads after testing. | 120 default / 40 strict |
| **`huella_digital`** | XSS hunting does NOT apply — huella is passive external footprint only. The §1 gate should refuse, but if it doesn't, the xss-hunter must refuse with `refused_reason: "huella_digital engagement — active XSS testing not authorized"`. | N/A | N/A |

The engagement type also affects the **suspicion scoring thresholds**:

| Engagement type | confirmed threshold | high_suspicion range |
|---|---|---|
| `bug_bounty` | ≥ 75 | 50–74 |
| `contracted_pentest` | ≥ 65 | 40–64 |

### §4c — SSRF proof ceiling by engagement type

The SSRF proof ceiling adapts to the engagement's authorization level. Read
`engagement_type` (or `tier`) from `memory/programs/<slug>.json`:

| Engagement type | Proof ceiling (STOP here) | Phases allowed | Candidate cap |
|---|---|---|---|
| **`bug_bounty`** | OOB callback to **your Burp Collaborator** (HTTP or DNS). Localhost response diff (status/length change when fetching 127.0.0.1). Cloud metadata reachability (169.254.169.254 responds differently — do NOT extract IAM credentials). No protocol handlers, no port timing. | Phases 0–2 + 4–5 (IP/filter bypass). Skip phase 3 (protocol) and phase 6 (blind timing). | 80 default / 20 strict |
| **`contracted_pentest`** | Everything in bug_bounty PLUS: protocol handler confirmation (`file:///etc/hostname` content — innocuous files only, NEVER `/etc/shadow` or credentials), internal service reachability map (which localhost ports respond — max 5 port probes), blind SSRF timing (consistent response-time delta). Still NO live credential extraction, NO SSRF→RCE chains, NO pivoting to exploit internal services. | All phases 0–6. | 120 default / 40 strict |
| **`huella_digital`** | SSRF hunting does NOT apply — huella is passive external footprint only. The §1 gate should refuse, but if it doesn't, the ssrf-hunter must refuse with `refused_reason: "huella_digital engagement — active SSRF testing not authorized"`. | N/A | N/A |

The engagement type also affects the **suspicion scoring thresholds**:

| Engagement type | confirmed threshold | high_suspicion range |
|---|---|---|
| `bug_bounty` | ≥ 75 | 50–74 |
| `contracted_pentest` | ≥ 65 (lower bar — client authorized deeper testing) | 40–64 |

If confirming a finding would require crossing a ceiling, **stop at the ceiling and report
the lower-but-honest impact** with a note that full impact was not exploited per program rules
(triagers respect this; it matches MELI's Tier-3 "no exploitation beyond confirmation" and
standard safe-harbor expectations).

---

## §5 — Evidence & decoupling

- Raw requests/responses, tokens, OOB logs → `/mnt/files/bb-agent/<slug>/webvuln/<class>/<UTC-ts>/` mode `0700`. Never in git.
- Redacted candidate JSON → `out/<slug>/webvuln/<class>/<UTC-ts>.json` (`out/` is gitignored).
- Each candidate carries `ownership_status: "UNVERIFIED"`. For a finding on a host under an in-scope wildcard, `ownership-verifier`'s `in_scope_subdomain_override` auto-promotes to owned — same as endpoint-hunter.
- Hunters do **not** verify ownership and do **not** draft reports. `report-drafter` is the only drafter; **no auto-submit** ever.
- Redact secrets/tokens in candidate JSON to `<first-4>…<last-4>`; raw stays under `/mnt/files`.

---

## §6 — Step-0 boilerplate (every active hunter pastes this)

```
0. Load learned rules + GATE
   - Read memory/rules.json → rules.<this_agent> (create skeleton if missing).
   - Read memory/programs/<slug>.json. If missing → stop: "<agent>: program <slug> not ingested — run /program-load first."
   - HARD GATE (§1): if automated_tools_allowed==false OR explicit_scanner_ban==true OR
     (safe_harbor==false AND no operator go) → write empty-candidates output with
     refused_reason and STOP. Never proceed to any active step.
   - Read rules.rate_limit_cap_rps (default 2 for active tier).
   - Confirm Burp MCP is reachable (mcp__burp__* available). If not → stop with a clear
     "Burp MCP not connected in this session" error.
   - Require an auth-context for authenticated classes (see auth-context); if absent and the
     class needs auth → note degraded (unauth-only) coverage in summary.notes.
```
