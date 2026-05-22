# Bug Bounty Agent — Tool Inventory

Generated 2026-05-11. Updated 2026-05-22 (Phase 2 — endpoint-hunter agent added).
Single source of truth for which tool lives where. Subagents MUST use the full paths below — do not rely on PATH order.

## Subagent → tool map (quick reference)

| Subagent | Primary tools | Active probes? | Compliance gates |
|---|---|---|---|
| `program-scope-parser` | WebFetch + arkadiyt dump | passive only | n/a |
| `program-scout` | WebFetch (one-time dump) | passive only | n/a |
| `secret-hunter` | trufflehog (A,B) + gitleaks (B.5) + noseyparker (C) + `gh api` | passive only (GitHub-side, not against program) | `automated_tools_allowed`, `mass_scanning_allowed` |
| `bucket-hunter` | s3scanner + aws s3api recheck | passive only (AWS-side) | `bucket_listing_allowed`, `mass_scanning_allowed` |
| `takeover-hunter` | subfinder + amass + crt.sh + dnsx + subzy + curl (body recheck) + nuclei (gated) | passive enum + body recheck curl + gated nuclei | `automated_tools_allowed`, `explicit_scanner_ban`, `rate_limit_cap_rps` |
| `endpoint-hunter` (Phase 2) | gau + grep + httpx (gated) + curl body fetch + nuclei (gated) | passive enum + gated active live-probe | `automated_tools_allowed`, `explicit_scanner_ban`, `rate_limit_cap_rps` |
| `ownership-verifier` | gh api + gau + dig | passive only | n/a |
| `report-drafter` | (no scanning — reads candidate JSONs + ownership cache) | n/a | path-leak filter |
| `retro-analyzer` | (no scanning — analyzes engagement artifacts) | n/a | n/a |

## Binary paths

| Tool | Full path | Version | Purpose |
|---|---|---|---|
| bbot | `/home/kenny/.local/bin/bbot` | 2.8.4 | Multi-module recon orchestrator |
| trufflehog | `/home/kenny/go/bin/trufflehog` | 3.95.2 | Verified-secret scanner (use `--results=verified` on 3.95.x; older `--only-verified` flag was renamed). Used by `secret-hunter` Pass A (`--org=<X>`) + Pass B (`filesystem` on cloned repos). |
| gitleaks | `/home/kenny/go/bin/gitleaks` | latest | Second-pass secret scanner, different ruleset (RSA PEM, base64-encoded JWT-shaped, JDBC connection strings, custom regex patterns). **Phase 1 integration (2026-05-21):** used by `secret-hunter` Pass B.5 on cloned repos with `--no-git --redact --no-banner`. Filesystem-only; Pass C noseyparker covers git history. |
| noseyparker | `/home/kenny/go/bin/noseyparker` | 0.24.0 | Fast historical-commit secret scanner. Used by `secret-hunter` Pass C — single shared datastore across all Pass B clones, one `report --format json` call at the end. |
| subfinder | `/home/kenny/go/bin/subfinder` | v2.6.8 | Passive subdomain enumeration. Used by `takeover-hunter` Step 4.1 as the primary source (~50 indexed passive sources). |
| httpx | `/home/kenny/go/bin/httpx` | v1.9.0 | HTTP probing (ProjectDiscovery, NOT the python lib). **Phase 2 integration (2026-05-22):** used by `endpoint-hunter` Step 6 for live-probe of gau-derived sensitive-path candidates. GATED on `automated_tools_allowed=true` AND `explicit_scanner_ban != true`. Rate-limited via `-rate-limit ${rate_limit_cap_rps:-5}`. NOT used by takeover-hunter (curl body-recheck is the only allowed HTTP probe there). |
| nuclei | `/home/kenny/go/bin/nuclei` | v3.3.10 | Template-based vuln + takeover scanner with ~9000 templates. **Phase 1 integration (2026-05-21):** `takeover-hunter` Step 6.7 with `-t http/takeovers/`, GATED on `automated_tools_allowed=true` AND `explicit_scanner_ban != true`. **Phase 2 integration (2026-05-22):** `endpoint-hunter` Step 8 with `-t http/exposures/ -t http/misconfiguration/`, same gates. Templates restricted to those two directories — broader nuclei classes (weak-creds, vulnerability scanning) remain out of bb-agent's passive-recon scope. |
| dnsx | `/home/kenny/go/bin/dnsx` | latest | DNS resolution toolkit. Used by `takeover-hunter` Step 5 for CNAME extraction. **Quirk:** the May 2026 binary hangs on `-l <file>`; pipe via stdin instead. |
| katana | `/home/kenny/go/bin/katana` | latest | Modern web crawler. NOT used by endpoint-hunter Phase 2 (relies on gau-archived URLs + nuclei templates instead). May be added in a future phase if archived-URL coverage proves insufficient on programs with newer/less-indexed sites. |
| naabu | `/home/kenny/go/bin/naabu` | latest | Fast port scanner. NOT used — active by definition; doesn't fit passive recon. |
| pdtm | `/home/kenny/go/bin/pdtm` | latest | ProjectDiscovery tool manager |
| subzy | `/home/kenny/go/bin/subzy` | latest | Subdomain takeover scanner (uses can-i-take-over-xyz). Used by `takeover-hunter` Step 6 as the primary fingerprint engine. CLI: `subzy run --targets <file> --output <file>.json --vuln --hide_fails --concurrency 20 --timeout 15`. `--vuln` saves only VULNERABLE entries. **All subzy matches must pass the Step 6.5 body-recheck gate** (`rule-takeover_hunter-subzy_body_recheck_required-e91f7`) before reaching report-drafter. |
| amass | `/home/kenny/.local/bin/amass` | older | OWASP subdomain enumeration. **Phase 1 integration (2026-05-21):** used by `takeover-hunter` Step 4.2 alongside subfinder + crt.sh. **Must run `amass enum -passive`** — active mode does ASN sweeps and DNS bruteforce which violate the passive-only rule. |
| s3scanner | `/home/kenny/go/bin/s3scanner` | dev | S3 bucket permission scanner. Used by `bucket-hunter` Pass A. **Always rechecked via `aws s3api list-objects-v2 --no-sign-request`** at Step 4.5 — `rule-bucket_hunter-s3scanner_acl_recheck_required-37651`. |
| cloud_enum | `/usr/local/bin/cloud_enum` | system | Multi-cloud (AWS/GCS/Azure) enumerator. Used by `bucket-hunter` Pass B as a fallback if Pass A returns zero hits — has not triggered in any engagement to date. |
| theHarvester-h | `/home/kenny/.local/bin/theHarvester-h` | 4.10.1 | Email/employee OSINT |
| gh | `/home/kenny/.local/bin/gh` | 2.92.0 | GitHub CLI for API queries |
| gau | `/home/kenny/go/bin/gau` | 2.2.4 | Get All URLs (Wayback + CC + AlienVault + URLScan). Used by `ownership-verifier` Check B for asset reference history. **Phase 2 integration (2026-05-22):** primary discovery surface for `endpoint-hunter` Step 4 — queries Wayback + CommonCrawl + AlienVault OTX + URLScan in parallel for each in-scope seed domain. Fully passive (no requests against program infra). |
| waybackurls | `/home/kenny/go/bin/waybackurls` | latest | Wayback URL dumper. Redundant with `gau` (gau queries Wayback as one of its providers). Not used by any current agent. |
| assetfinder | `/home/kenny/go/bin/assetfinder` | latest | Lightweight subdomain finder |
| cariddi | `/home/kenny/go/bin/cariddi` | latest | Web crawl + secret extractor in one pass |

## Important PATH notes

- `~/.local/bin/httpx-py` is the Python httpx library CLI (renamed from `httpx`). Don't use it for security work.
- Always invoke tools by full path in subagent scripts to avoid PATH-shadowing surprises.

## Auxiliary binaries also available

- `dig`, `curl`, `jq` — standard utilities. `curl` is used by `takeover-hunter` Step 6.5 for the live body-recheck gate (`curl -s --max-time 10 -L -k`); `jq` is used everywhere for JSON parsing.
- `git` — for cloning repos. Always shallow (`--depth=1`) for Pass B; full unshallow happens in Pass C for noseyparker history.
- `aws` — `/home/kenny/.local/bin/aws` (aws-cli/1.37.2). Used by `bucket-hunter` Step 4.5 for the anonymous list-objects-v2 recheck that defangs s3scanner ACL false positives: `aws s3api list-objects-v2 --no-sign-request --bucket <n> --max-items 1`. Never call with credentials; `--no-sign-request` is mandatory for compliance with the "passive-only" hard rule.
- `~/.bbot/tools/` — bbot's bundled binaries (httpx 2022, trufflehog 3.90.8, massdns, ffuf, gowitness, jadx, nuclei, retirejs, smuggler, telerik). Older but usable if needed.

## Web services (not local binaries)

- **crt.sh** — Cert Transparency log direct query. **Phase 1 integration (2026-05-21):** used by `takeover-hunter` Step 4.3 alongside subfinder + amass for passive subdomain enumeration. Pattern: `curl -s --max-time 30 "https://crt.sh/?q=%25.<seed>&output=json"` → `jq -r '.[]?.name_value'` → dedupe. **Rate limit:** no auth, ~10 req/min — be patient on 503 / empty JSON, log and continue with subfinder+amass only.
- **Wayback Machine via `gau` binary** — `gau` is the local binary that fronts Wayback + CommonCrawl + URLScan + AlienVault OTX. Used by `ownership-verifier` Check B for asset reference history. Phase 2 endpoint-hunter will use it as a discovery surface for `/.env*`-class archived URLs.

## API key file

`~/.config/bbot/secrets.yml` — currently holds:
- GitHub PAT (5 module entries)
- Postman PAK

⚠️ Rotate keys when done with each engagement.

## Slug-prefix convention

Programs from different platforms can share a brand name (`cloudflare` exists on multiple platforms). To prevent ownership-cache / submissions-log collisions across platforms, non-H1 programs are stored with a per-platform prefix in `memory/programs/<slug>.json`:

| Platform | Slug form | Example | URL pattern parsed |
|---|---|---|---|
| HackerOne | bare handle | `cloudflare` | `https://hackerone.com/<handle>` |
| Bugcrowd | `bc-<engagement-slug>` | `bc-t-mobile` | `https://bugcrowd.com/engagements/<engagement-slug>` |
| Intigriti | `int-<handle>` | `int-aikido` | `https://www.intigriti.com/programs/<company-handle>/<handle>/detail` |

The prefix is stripped only for the GitHub-org guess in `ownership-verifier` (the GH org is `t-mobile`, not `bc-t-mobile`). Everywhere else — ownership-cache filenames, submissions log, program JSON, candidate scan output paths — the prefixed slug is used verbatim.

When adding a new platform, register the prefix in `ownership-verifier.md` Step 1 (the prefix-strip list) and in this table.

## Output convention

All scan output goes under `/mnt/files/bb-agent/<program>/<scan-type>/<timestamp>/`.
Never write to `~/.bbot/scans/` (root partition is tight).

## Compliance hard rules (apply to ALL subagents)

1. **One non-destructive validation call per finding source.** Track in conversation state. Refuse second calls.
2. **No bucket file downloads.** ListBucket OK. GetObject NOT OK.
3. **No active mass scanning.** Programs that ban "massive automated scans" → restrict to passive modules only.
4. **Verify ownership BEFORE drafting report.** GitHub code search + Wayback + DNS chain. If `UNOWNED`, abort.
5. **0-day age gate.** Block CVE reports for vulns published <30 days ago unless program allows.
