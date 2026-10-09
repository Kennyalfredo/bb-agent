# bb-agent — Tool Inventory

Single source of truth for which tools bb-agent uses and how they interact.
Verify each tool is installed and on PATH before running engagements (`which <tool>`).
See `SETUP.md` for installation instructions.

## Subagent → tool map (quick reference)

| Subagent | Primary tools | Active probes? | Compliance gates |
|---|---|---|---|
| `program-scope-parser` | WebFetch + arkadiyt dump | passive only | n/a |
| `program-scout` | WebFetch (one-time dump) | passive only | n/a |
| `secret-hunter` | trufflehog (A,B) + gitleaks (B.5) + noseyparker (C) + `gh api` | passive only (GitHub-side, not against program) | `automated_tools_allowed`, `mass_scanning_allowed` |
| `bucket-hunter` | s3scanner + aws s3api recheck | passive only (AWS-side) | `bucket_listing_allowed`, `mass_scanning_allowed` |
| `takeover-hunter` | subfinder + amass + crt.sh + dnsx + subzy + curl (body recheck) + nuclei (gated) | passive enum + body recheck curl + gated nuclei | `automated_tools_allowed`, `explicit_scanner_ban`, `rate_limit_cap_rps` |
| `endpoint-hunter` | gau + **waymore** (`-mode U`) + grep + httpx (gated) + curl body fetch + nuclei (gated) | passive enum + gated active live-probe | `automated_tools_allowed`, `explicit_scanner_ban`, `rate_limit_cap_rps` |
| `ownership-verifier` | gh api + gau + dig + **theHarvester (gh_account assets only)** | passive only | n/a |
| `report-drafter` | (no scanning — reads candidate JSONs + ownership cache) | n/a | path-leak filter |
| `retro-analyzer` | (no scanning — analyzes engagement artifacts) | n/a | n/a |
| `footprint-hunter` (Huella Digital) | bbot (passive) + subfinder/amass/crt.sh + dnsx + httpx (`-screenshot`) + gowitness + theHarvester (NO linkedin) + dig (DNSBL) + HIBP/breach (pluggable) | passive enum + **light-active** (httpx homepage probe + 1 screenshot/host + DNSBL) | `light_active_allowed`, `screenshots_allowed`, `credential_validation_allowed` (always false), `heavy_active_allowed` (false), `rate_limit_cap_rps` |
| `huella-reporter` (Huella Digital) | (no scanning — reads footprint + 4 hunt outputs + LinkedIn manual paste + ownership cache) | n/a | no-local-paths filter; vendor-cred attribution |

## Tool catalog

Each tool below must be on PATH. Use `which <tool>` to verify after install.

| Tool | Install | Purpose |
|---|---|---|
| bbot | `pipx install bbot` | Multi-module recon orchestrator |
| trufflehog | `go install github.com/trufflesecurity/trufflehog/v3@latest` | Verified-secret scanner (use `--results=verified` on 3.95.x; older `--only-verified` flag was renamed). Used by `secret-hunter` Pass A (`--org=<X>`) + Pass B (`filesystem` on cloned repos). |
| gitleaks | `go install github.com/gitleaks/gitleaks/v8@latest` | Second-pass secret scanner, different ruleset (RSA PEM, base64-encoded JWT-shaped, JDBC connection strings, custom regex patterns). Used by `secret-hunter` Pass B.5 on cloned repos with `--no-git --redact --no-banner`. Filesystem-only; Pass C noseyparker covers git history. |
| noseyparker | `cargo install noseyparker` or download from [GitHub releases](https://github.com/praetorian-inc/noseyparker/releases) | Fast historical-commit secret scanner. Used by `secret-hunter` Pass C — single shared datastore across all Pass B clones, one `report --format json` call at the end. |
| subfinder | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | Passive subdomain enumeration. Used by `takeover-hunter` Step 4.1 as the primary source (~50 indexed passive sources). |
| httpx | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` | HTTP probing (**ProjectDiscovery httpx**, NOT the Python `httpx` library — see PATH notes below). Used by `endpoint-hunter` Step 6 for live-probe of gau-derived sensitive-path candidates. GATED on `automated_tools_allowed=true` AND `explicit_scanner_ban != true`. Rate-limited via `-rate-limit ${rate_limit_cap_rps:-5}`. NOT used by takeover-hunter (curl body-recheck is the only allowed HTTP probe there). |
| nuclei | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | Template-based vuln + takeover scanner with ~9000 templates. `takeover-hunter` Step 6.7 with `-t http/takeovers/`, GATED on `automated_tools_allowed=true` AND `explicit_scanner_ban != true`. `endpoint-hunter` Step 8 with `-t http/exposures/ -t http/misconfiguration/`, same gates. Templates restricted to those two directories — broader nuclei classes (weak-creds, vulnerability scanning) remain out of bb-agent's passive-recon scope. |
| dnsx | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` | DNS resolution toolkit. Used by `takeover-hunter` Step 5 for CNAME extraction. **Quirk:** some builds hang on `-l <file>`; pipe via stdin instead. |
| katana | `go install github.com/projectdiscovery/katana/cmd/katana@latest` | Modern web crawler. NOT currently used — may be added if archived-URL coverage proves insufficient on newer programs. |
| naabu | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` | Fast port scanner. NOT used — active by definition; doesn't fit passive recon. |
| pdtm | `go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest` | ProjectDiscovery tool manager (alternative: install all PD tools via `pdtm -install-all`). |
| subzy | `go install github.com/PentestPad/subzy@latest` | Subdomain takeover scanner (uses can-i-take-over-xyz). Used by `takeover-hunter` Step 6 as the primary fingerprint engine. CLI: `subzy run --targets <file> --output <file>.json --vuln --hide_fails --concurrency 20 --timeout 15`. `--vuln` saves only VULNERABLE entries. **All subzy matches must pass the Step 6.5 body-recheck gate** (`rule-takeover_hunter-subzy_body_recheck_required-e91f7`) before reaching report-drafter. |
| amass | `go install github.com/owasp-amass/amass/v4/...@master` | OWASP subdomain enumeration. Used by `takeover-hunter` Step 4.2 alongside subfinder + crt.sh. **Must run `amass enum -passive`** — active mode does ASN sweeps and DNS bruteforce which violate the passive-only rule. |
| s3scanner | `go install github.com/sa7mon/S3Scanner@latest` | S3 bucket permission scanner. Used by `bucket-hunter` Pass A. **Always rechecked via `aws s3api list-objects-v2 --no-sign-request`** at Step 4.5 — `rule-bucket_hunter-s3scanner_acl_recheck_required-37651`. |
| cloud_enum | `pip install cloud_enum` | Multi-cloud (AWS/GCS/Azure) enumerator. Used by `bucket-hunter` Pass B as a fallback if Pass A returns zero hits. |
| theHarvester | `pipx install theHarvester` | Email/employee OSINT. Used by `ownership-verifier` Step 3.5 (Check A.5) when `asset_class == "gh_account"`. Run once per program (90-day employee-cache TTL at `memory/employee-cache/<slug>.json`). MANDATORY flags: `-b duckduckgo,crtsh,certspotter,dnsdumpster` (passive search engines + cert-transparency + DNS records). ⚠️ theHarvester 4.10+ rejects `google` and `bing` as "Invalid source" and ABORTS the entire run if either is passed — they were dropped from the provider set. **NEVER use `-b linkedin`, `-b linkedin_links`, or `-b companies`** — LinkedIn ToS prohibits scraping; researcher account suspension risk. The remaining providers cover the same employee-email signal. Output is cross-referenced against the GH account's public profile (name/email/company) to attribute the account to a real program employee — boosts Check A from negative to positive when matched. |
| gh | [GitHub CLI installer](https://cli.github.com/) | GitHub CLI for API queries. |
| gau | `go install github.com/lc/gau/v2/cmd/gau@latest` | Get All URLs (Wayback + CC + AlienVault + URLScan). Used by `ownership-verifier` Check B for asset reference history. Primary discovery surface for `endpoint-hunter` Step 4 — queries Wayback + CommonCrawl + AlienVault OTX + URLScan in parallel for each in-scope seed domain. Fully passive (no requests against program infra). |
| waybackurls | `go install github.com/tomnomnom/waybackurls@latest` | Wayback URL dumper. Redundant with `gau` (gau queries Wayback as one of its providers). Not used by any current agent. |
| waymore | `pipx install waymore` | "Find way more from the Wayback Machine" (@xnl-h4ck3r). Superset of `gau`: archived-URL discovery from Wayback + CommonCrawl + AlienVault OTX + URLScan **+ VirusTotal + Intelligence X** (the last two need API keys in `~/.config/waymore/config.yml`). Two modes: `-mode U` (URLs only — the `gau`-equivalent discovery surface) and `-mode R` (downloads the archived **response bodies**, e.g. old JS/config/`.env` snapshots — useful for finding secrets/endpoints removed from the live site). `endpoint-hunter` Step 4 runs `-mode U` as a complementary discovery source merged+deduped with gau. `footprint-hunter` §DNS surface runs `-mode U` and extracts in-scope hostnames from the archived URLs. Both integrations are optional + `timeout`-guarded (skip on absent/stall). Fully passive (queries public archive aggregators only, never program infra). **KNOWN ISSUE: may hang on the Wayback CDX query in some environments — the timeout guard makes a stall harmless.** `-mode R` is OFF by default (heavier; overlaps secret-hunter scope) — enable only on explicit operator request. Config lives at `~/.config/waymore/config.yml`. |
| assetfinder | `go install github.com/tomnomnom/assetfinder@latest` | Lightweight subdomain finder. |
| cariddi | `go install github.com/edoardottt/cariddi/cmd/cariddi@latest` | Web crawl + secret extractor in one pass. |
| gowitness | `go install github.com/sensepost/gowitness@latest` | Headless web screenshotter. Used by `footprint-hunter` §Web portals as the fallback screenshot engine when `httpx -screenshot` is unstable. `gowitness scan file -f <hosts> --screenshot-path <dir>`. httpx also has a native `-screenshot -system-chrome -srd <dir>` (preferred — one tool for probe+shot). Screenshots are a **light-active** touch (loads the public homepage) — gated on `screenshots_allowed`. |
| maigret | `pipx install maigret` | Username/handle hunter across ~3158 sites. Used by `footprint-hunter` §Social (Technique B) for brand-handle enumeration — finds social/web profiles NOT linked from the client site (incl. impersonation/squatting). Anonymous **public-URL existence checks only** (no auth, no API keys) → matches the "anonymous GET only" mandate. MANDATORY flags: `--top-sites 300 --timeout 8 --retries 1 --no-recursion --no-extracting --no-progressbar --no-color -J simple -fo <dir>`. Parse `report_<handle>_simple.json` → keep entries where `.status.status=="Claimed" AND .site.similarSearch != true` (drops search-query pseudo-hits like Google Scholar). ⚠️ **Handle-enum results are CANDIDATES, not confirmed** — maigret has false positives (e.g. geeksforgeeks); tag `confidence: "candidate"` and flag for manual visual confirmation in the report. **NEVER feed LinkedIn** (`--ignore-ids` / exclude any `linkedin` site) — LinkedIn stays on the manual-paste path (absolute scraping ban). Touches third-party platforms → gated on `social_enum_allowed`. |

## PATH notes

- **httpx naming conflict:** The Go-based ProjectDiscovery `httpx` (used by bb-agent) and the Python `httpx` library both install a binary called `httpx`. If both are installed, the wrong one may shadow the other. Verify with `httpx -version` — ProjectDiscovery httpx prints a version like `v1.x.x` with `projectdiscovery` in the output. If the Python version is on PATH, rename it (e.g. `httpx-py`) or adjust your PATH order so Go binaries come first.
- Verify each tool individually with `which <tool>` before running an engagement.

## Auxiliary binaries (system packages)

- `dig`, `curl`, `jq` — standard utilities (`apt install dnsutils curl jq`). `curl` is used by `takeover-hunter` Step 6.5 for the live body-recheck gate (`curl -s --max-time 10 -L -k`); `jq` is used everywhere for JSON parsing.
- `git` — for cloning repos. Always shallow (`--depth=1`) for Pass B; full unshallow happens in Pass C for noseyparker history.
- `aws` — AWS CLI (`pip install awscli` or [official installer](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)). Used by `bucket-hunter` Step 4.5 for the anonymous list-objects-v2 recheck that defangs s3scanner ACL false positives: `aws s3api list-objects-v2 --no-sign-request --bucket <n> --max-items 1`. Never call with credentials in passive mode; `--no-sign-request` is mandatory for compliance with the "passive-only" hard rule.

## Web services (not local binaries)

- **crt.sh** — Cert Transparency log direct query. Used by `takeover-hunter` Step 4.3 alongside subfinder + amass for passive subdomain enumeration. Pattern: `curl -s --max-time 30 "https://crt.sh/?q=%25.<seed>&output=json"` → `jq -r '.[]?.name_value'` → dedupe. **Rate limit:** no auth, ~10 req/min — be patient on 503 / empty JSON, log and continue with subfinder+amass only.
- **Wayback Machine via `gau`** — `gau` fronts Wayback + CommonCrawl + URLScan + AlienVault OTX. Used by `ownership-verifier` Check B and `endpoint-hunter` Step 4.
- **Archive aggregation via `waymore`** — complements `gau` in `endpoint-hunter` Step 4 with deeper Wayback pagination + VirusTotal/IntelX providers. When both run, merge+dedupe their URL output before the Step-5 sensitive-path grep. Add VT/IntelX API keys to `~/.config/waymore/config.yml` to light up those extra providers (Wayback + CC + OTX + URLScan work key-less).

## API keys

Several tools benefit from API keys for broader coverage. Configure them in each tool's own config location:

| Config file | Keys | Required? |
|---|---|---|
| `~/.config/bbot/secrets.yml` | GitHub PAT, Postman PAK, others | GitHub PAT strongly recommended |
| `~/.config/waymore/config.yml` | VirusTotal, Intelligence X | Optional (Wayback/CC/OTX/URLScan work key-less) |
| `~/.config/subfinder/provider-config.yaml` | Various passive sources | Optional (improves coverage) |
| `HIBP_API_KEY` env var | HaveIBeenPwned | Optional (breach section degrades to "no configurado" without it) |

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

All scan output goes under `$BB_AGENT_DATA/<program>/<scan-type>/<timestamp>/`.

The `BB_AGENT_DATA` environment variable defaults to `./data` (relative to the repo root). The bootstrap script (`scripts/bootstrap.sh`) creates this directory. If you have a separate data partition (e.g. `/mnt/files/bb-agent/`), set `BB_AGENT_DATA` to point there.

Avoid writing scan output to bbot's internal `~/.bbot/scans/` directory.

## Compliance hard rules (apply to ALL subagents)

1. **One non-destructive validation call per finding source.** Track in conversation state. Refuse second calls.
2. **No bucket file downloads.** ListBucket OK. GetObject NOT OK.
3. **No active mass scanning.** Programs that ban "massive automated scans" → restrict to passive modules only.
4. **Verify ownership BEFORE drafting report.** GitHub code search + Wayback + DNS chain. If `UNOWNED`, abort.
5. **0-day age gate.** Block CVE reports for vulns published <30 days ago unless program allows.

## Cloud pentest tooling (AWS-focused)

Arsenal for **authenticated cloud-configuration pentests** (contracted engagements, credential-gated — NOT bug-bounty passive recon). This tier is authenticated by definition: it needs an in-scope AWS access-key/secret or an assumable role. Credentials live in an AWS CLI profile (see below), never in the repo or in chat.

| Tool | Install | Purpose |
|---|---|---|
| aws | [AWS CLI installer](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) | Identity (`sts get-caller-identity`), enumeration, data access, `iam simulate-principal-policy`. |
| prowler | `pipx install prowler` | ⭐ Configuration/posture audit — CIS/PCI/NIST/SOC2 checks (`prowler aws -p <profile>`). The core of cloud-config testing. NOTE: if both pip and pipx copies exist, ensure the pipx version wins on PATH. |
| scout | `pipx install scoutsuite` | Multi-cloud posture audit with a navigable HTML report (`scout aws --profile <profile>`). Visual complement to Prowler. |
| pacu | `pipx install pacu` | Offensive AWS framework: `iam__enum_permissions`, `iam__privesc_scan`, modular exploitation. Import keys with `import_keys`. |
| cloudfox | Download from [GitHub releases](https://github.com/BishopFox/cloudfox/releases) | "What can I do with these creds" — enumeration + attack-path surfacing (`cloudfox aws --profile <profile> all-checks`). |
| pmapper | `pipx install principalmapper` | IAM privilege-escalation **graph** — PassRole/AssumeRole chains Prowler can't see (`pmapper --profile <p> graph create` → `query`/`analysis`/`visualize`). ⚠️ **Python 3.12 patch required:** its `util/case_insensitive_dict.py` uses `from collections import Mapping` (removed in py3.10) → change to `from collections.abc import Mapping, MutableMapping`. **A `pipx reinstall`/`upgrade` of principalmapper WIPES this patch — re-apply it.** |
| cloudsplaining | `pipx install cloudsplaining` | IAM policy least-privilege assessment (dangerous wildcards, privesc, resource-exposure). `cloudsplaining download --profile <p>` then `scan`. |
| IAM Access Analyzer | `aws accessanalyzer` (built into AWS CLI) | AWS-native, **authoritative** external/public-access findings (buckets/roles/keys shared outside the account/org). `list-analyzers` per region → `list-findings`. SecurityAudit-readable. **If NO account analyzer is enabled, that absence is itself a finding** (no continuous external-access monitoring). Non-redundant with Prowler/ScoutSuite — settles "is it really public/shared" without manual condition triage. |
| GuardDuty | `aws guardduty` (built into AWS CLI) | Runtime threat-detection findings (the one non-config dimension). `list-detectors` per region → `get-findings` top-by-severity. SecurityAudit-readable; `get-detector` confirms the detector's status. |
| boto3 / policyuniverse | `pip install boto3 policyuniverse` | Ad-hoc AWS scripting + IAM policy analysis primitives. Powers the FP-triage scripts (SG→live-instance correlation, SNS/S3 policy-condition classification, RDS PubliclyAccessible check). |

The above is orchestrated by the **`cloud-auditor`** subagent via the **`/audit-cloud <slug> <profile>`** command. cloud-auditor runs the non-redundant set (Prowler + pmapper + cloudfox + credential report + Access Analyzer + GuardDuty; ScoutSuite/cloudsplaining kept for their HTML) and applies the mandatory false-positive triage before writing `out/<slug>/cloud/<ts>/FINDINGS.md`. Deliverable = `/informe <slug> tecnico` (Typst). **pacu** + **enumerate-iam** are intentionally NOT wired in — pacu's value is write/exploitation (out of scope for the read-only role) and enumerate-iam is redundant when SecurityAudit lets us read policies directly.

**Credential handling (hard rules for this tier):**
- Store creds in an AWS CLI **named profile** (`~/.aws/credentials` under `[<engagement>]`), set up by the operator via `! aws configure --profile <engagement>` so secrets never transit the chat/transcript. Every tool takes `--profile <engagement>`.
- First call on any new creds is always `aws sts get-caller-identity` (read-only) to confirm the identity + account before anything else.
- Read-only/enumeration by default. Any write, privesc *execution*, persistence, or data exfil requires explicit per-action operator authorization (mirrors the pentest-playbook proof ceiling — confirm the path, don't detonate it). No snapshot-sharing to external accounts, no key minting, no policy edits without sign-off.
- Rotate/revoke the engagement keys when the engagement closes; delete the profile.
- Deliverable is a SYSCLOUDSEC **Typst** report via Eje 3 (`/informe <slug> tecnico`), not loose markdown.

## Huella Digital mode (`/domain`)

A second engagement mode for **client work-projects**, distinct from bug-bounty passive-recon. Triggered by `/domain <domain>`; synthesizes a `engagement_type:"huella_digital"` scope JSON, runs the four existing hunts PLUS `footprint-hunter`, then `huella-reporter` assembles a Spanish **SYSCLOUDSEC "Informe de Huella Digital"** at `out/<slug>/reports/huella-digital-<ts>.md`. Authorization = bare-domain-is-go (the user supplying the domain is the authorization).

**Capability tiers (encoded as scope-rule flags, not hardcoded):**
- **Passive** (always): bbot passive presets, subfinder/amass/crt.sh, **waymore (`-mode U`, archive-derived hostnames → §DNS surface; optional, timeout-guarded)**, dnsx, gau, theHarvester (allowed providers only), DNSBL via dig, HIBP/breach lookup.
- **Light-active** (`light_active_allowed:true`, default ON for `/domain`): single httpx homepage probe per host + one web screenshot/host. These load only public homepages — distinct from the bug-bounty mode's passive-only constraint.
- **Social handle-enum** (`social_enum_allowed:true`, default ON for `/domain`): maigret brand-handle existence checks across ~300 third-party social/web platforms. This is the ONE tier that touches **third parties** (not client infra) — anonymous public-URL GETs only, no auth, no scraping. Distinct flag so an engagement can keep client-only by setting it `false` (then §Social falls back to footer-scrape of the client's own pages only).
- **Heavy-active** (`heavy_active_allowed:false`, OFF): no nuclei CVE/exploit, no fuzzing, no port sweeps.
- **Credential validation** (`credential_validation_allowed:false`, **HARD-OFF in this build**): leaked creds are LISTED only, `Estado=DESCONOCIDA`, NEVER login-tested. Validation requires separate written client authorization.

**Standing bans that still apply in this mode:**
- **LinkedIn automation is banned** (theHarvester `-b linkedin/linkedin_links/companies`, bbot LinkedIn scraping) — ToS / account-suspension. LinkedIn employee data enters via a **manual paste** the `/domain` command collects → `out/<slug>/footprint/linkedin-manual.json` → §1.4.3.
- **No bucket downloads, no auth bypass, no exploitation.**

**Breach source is pluggable.** Default HIBP (`/api/v3/breacheddomain/<apex>`, needs `HIBP_API_KEY` — returns breach names, no passwords). bbot `dehashed`/`credshed` modules can be wired via `~/.config/bbot/secrets.yml` to populate plaintext (still listed only, never validated). Unconfigured → breach section degrades to "no configurado".
