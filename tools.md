# Bug Bounty Agent — Tool Inventory

Generated 2026-05-11. Single source of truth for which tool lives where.
Subagents MUST use the full paths below — do not rely on PATH order.

## Binary paths

| Tool | Full path | Version | Purpose |
|---|---|---|---|
| bbot | `/home/kenny/.local/bin/bbot` | 2.8.4 | Multi-module recon orchestrator |
| trufflehog | `/home/kenny/go/bin/trufflehog` | 3.95.2 | Verified-secret scanner (use `--only-verified`) |
| gitleaks | `/home/kenny/go/bin/gitleaks` | latest | Second-pass secret scanner, different ruleset |
| noseyparker | `/home/kenny/go/bin/noseyparker` | 0.24.0 | Fast historical-commit secret scanner |
| subfinder | `/home/kenny/go/bin/subfinder` | v2.6.8 | Passive subdomain enumeration |
| httpx | `/home/kenny/go/bin/httpx` | v1.9.0 | HTTP probing (ProjectDiscovery, NOT the python lib) |
| nuclei | `/home/kenny/go/bin/nuclei` | v3.3.10 | Template-based vuln + takeover scanner |
| dnsx | `/home/kenny/go/bin/dnsx` | latest | DNS resolution toolkit |
| katana | `/home/kenny/go/bin/katana` | latest | Modern web crawler |
| naabu | `/home/kenny/go/bin/naabu` | latest | Fast port scanner |
| pdtm | `/home/kenny/go/bin/pdtm` | latest | ProjectDiscovery tool manager |
| subzy | `/home/kenny/go/bin/subzy` | latest | Subdomain takeover scanner (uses can-i-take-over-xyz) |
| amass | `/home/kenny/.local/bin/amass` | older | OWASP subdomain enumeration |
| s3scanner | `/home/kenny/go/bin/s3scanner` | dev | S3 bucket permission scanner |
| cloud_enum | `/usr/local/bin/cloud_enum` | system | Multi-cloud (AWS/GCS/Azure) enumerator |
| theHarvester-h | `/home/kenny/.local/bin/theHarvester-h` | 4.10.1 | Email/employee OSINT |
| gh | `/home/kenny/.local/bin/gh` | 2.92.0 | GitHub CLI for API queries |
| gau | `/home/kenny/go/bin/gau` | 2.2.4 | Get All URLs (Wayback + CC + AlienVault + URLScan) |
| waybackurls | `/home/kenny/go/bin/waybackurls` | latest | Wayback URL dumper |
| assetfinder | `/home/kenny/go/bin/assetfinder` | latest | Lightweight subdomain finder |
| cariddi | `/home/kenny/go/bin/cariddi` | latest | Web crawl + secret extractor in one pass |

## Important PATH notes

- `~/.local/bin/httpx-py` is the Python httpx library CLI (renamed from `httpx`). Don't use it for security work.
- Always invoke tools by full path in subagent scripts to avoid PATH-shadowing surprises.

## Auxiliary binaries also available

- `dig`, `curl`, `jq` — standard utilities
- `git` — for cloning repos
- `~/.bbot/tools/` — bbot's bundled binaries (httpx 2022, trufflehog 3.90.8, massdns, ffuf, gowitness, jadx, nuclei, retirejs, smuggler, telerik). Older but usable if needed.

## API key file

`~/.config/bbot/secrets.yml` — currently holds:
- GitHub PAT (5 module entries)
- Postman PAK

⚠️ Rotate keys when done with each engagement.

## Output convention

All scan output goes under `/mnt/files/bb-agent/<program>/<scan-type>/<timestamp>/`.
Never write to `~/.bbot/scans/` (root partition is tight).

## Compliance hard rules (apply to ALL subagents)

1. **One non-destructive validation call per finding source.** Track in conversation state. Refuse second calls.
2. **No bucket file downloads.** ListBucket OK. GetObject NOT OK.
3. **No active mass scanning.** Programs that ban "massive automated scans" → restrict to passive modules only.
4. **Verify ownership BEFORE drafting report.** GitHub code search + Wayback + DNS chain. If `UNOWNED`, abort.
5. **0-day age gate.** Block CVE reports for vulns published <30 days ago unless program allows.
