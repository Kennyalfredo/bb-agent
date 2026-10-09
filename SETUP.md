# Setup guide

Get bb-agent running from a fresh clone.

## Prerequisites

- **OS:** Linux (tested on Ubuntu 22.04+). macOS works for most tools; some Go binaries may need `GOOS=darwin`.
- **Claude Code:** install from [docs.anthropic.com](https://docs.anthropic.com/en/docs/claude-code). Verify: `claude --version`.
- **Go 1.21+:** most recon tools install via `go install`.
- **Python 3.10+** with `pip` and `pipx`.
- **GitHub CLI (`gh`):** authenticated (`gh auth login`). Required for secret-hunter GitHub code search.

## 1. Clone and bootstrap

```bash
git clone https://github.com/Kennyalfredo/bb-agent.git
cd bb-agent
bash scripts/bootstrap.sh
```

The bootstrap script creates `memory/` (local engagement data, gitignored), `out/` (scan outputs, gitignored), checks tool availability, and reports what's missing.

## 2. Install recon tools

Install all tools, or only the ones your workflow needs. The table below shows which hunters require which tools. Every tool should be on your `$PATH`.

### Core (needed by most hunters)

```bash
# GitHub CLI
# https://cli.github.com — install via package manager, then:
gh auth login

# ProjectDiscovery suite
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

# URL discovery
go install github.com/lc/gau/v2/cmd/gau@latest
pipx install waymore
```

> **httpx naming conflict:** ProjectDiscovery's `httpx` and the Python `httpx` library both install a binary named `httpx`. If you have both, rename the Python one (e.g., `httpx-py`) to avoid shadowing.

### Secret hunting

```bash
# TruffleHog — verified-secret scanner
go install github.com/trufflesecurity/trufflehog/v3@latest

# Gitleaks — complementary ruleset
go install github.com/gitleaks/gitleaks/v8@latest

# NoseyParker — fast historical-commit scanner
# Install from releases: https://github.com/praetorian-inc/noseyparker/releases
```

### Bucket + subdomain hunting

```bash
go install github.com/sa7mon/s3scanner@latest
go install github.com/LukaSikworkers/subzy@latest
# cloud_enum: pip install cloud_enum  OR  https://github.com/initstring/cloud_enum

# OWASP Amass
go install github.com/owasp-amass/amass/v4/...@latest
# IMPORTANT: always run with -passive flag only
```

### Digital footprint (Huella Digital mode)

```bash
# bbot — multi-module recon orchestrator
pipx install bbot

# theHarvester — email/employee OSINT
pipx install theHarvester
# Note: never use -b linkedin (ToS ban). Use: -b duckduckgo,crtsh,certspotter,dnsdumpster

# maigret — social-handle discovery
pipx install maigret
# Note: never feed LinkedIn sites. Use --top-sites 300

# gowitness — web screenshotter (installed with bbot, or standalone)
go install github.com/sensepost/gowitness/v3@latest
```

### Cloud audit tier (contracted engagements only)

```bash
# AWS CLI
pip install awscli  # or via package manager

# Prowler — CIS/PCI/NIST/SOC2 posture
pipx install prowler

# ScoutSuite — multi-cloud posture with HTML report
pipx install scoutsuite

# CloudFox — "what can I do with these creds"
# Install from releases: https://github.com/BishopFox/cloudfox/releases

# PMapper — IAM privilege-escalation graph
pipx install principalmapper
# WARNING: on Python 3.12+, patch util/case_insensitive_dict.py:
#   change "from collections import Mapping" to "from collections.abc import Mapping, MutableMapping"
#   A pipx reinstall/upgrade wipes this patch — re-apply it.

# Cloudsplaining — IAM least-privilege assessment
pipx install cloudsplaining
```

### Tool → hunter dependency map

| Hunter | Required tools | Optional |
|--------|---------------|----------|
| `secret-hunter` | trufflehog, gh, git | gitleaks, noseyparker |
| `bucket-hunter` | s3scanner, aws | cloud_enum |
| `takeover-hunter` | subfinder, dnsx, subzy, curl | amass, nuclei |
| `endpoint-hunter` | gau, curl | waymore, httpx, nuclei |
| `footprint-hunter` | subfinder, dnsx, httpx, dig | bbot, theHarvester, maigret, gowitness, waymore |
| `ownership-verifier` | gh, gau, dig | theHarvester |
| `cloud-auditor` | aws, prowler | pmapper, cloudfox, cloudsplaining, scoutsuite |
| `xss-hunter` | Burp MCP | dalfox |
| `sqli-hunter` | Burp MCP | sqlmap |
| `access-control-hunter` | Burp MCP | -- |

Missing tools don't crash the agent — the affected hunter reports a blocked step and continues with what's available.

## 3. MCP servers (optional, for active testing)

### Burp Suite MCP

Required for all active web-vuln hunters (`/hunt-xss`, `/hunt-sqli`, `/hunt-access`, `/hunt-ssrf`, etc.).

1. Install [Burp Suite Professional](https://portswigger.net/burp/pro)
2. Install the [Burp MCP extension](https://github.com/PortSwigger/burp-mcp) — enables Claude Code to send/receive HTTP requests through Burp
3. Start the MCP server (default: SSE at `http://127.0.0.1:9876/`)
4. Register in your Claude Code MCP settings:

```json
{
  "mcpServers": {
    "burp": {
      "type": "sse",
      "url": "http://127.0.0.1:9876/"
    }
  }
}
```

5. Restart Claude Code after registering.

### Playwright MCP (optional)

Used by `webvuln-surface` and `xss-hunter` for browser-based crawling and DOM XSS verification.

```bash
npm install -g @anthropic/playwright-mcp
```

Register in your MCP settings similar to Burp.

## 4. Offensive skills (optional)

bb-agent references `offensive-*` skills (e.g., `offensive-xss`, `offensive-sqli`, `offensive-ssrf`) for technique-specific guidance during active testing. These are Claude Code user-level skills stored in `~/.claude/skills/`.

Without them, hunters still work — they use their built-in playbook. The skills add deeper technique libraries (bypass patterns, WAF evasion, engine-specific payloads).

If you have access to these skills, install them in your `~/.claude/skills/` directory. Each is a directory with a `SKILL.md` file.

## 5. API keys (optional)

Some tools work better with API keys. None are required for basic operation.

| Key | Where to configure | Unlocks |
|-----|-------------------|---------|
| GitHub PAT | `gh auth login` | Higher rate limits for code search |
| HIBP API key | `$HIBP_API_KEY` env var | Breach-domain lookups in footprint-hunter |
| VirusTotal | `~/.config/waymore/config.yml` | Extra URL discovery source |
| Intelligence X | `~/.config/waymore/config.yml` | Extra URL discovery source |
| bbot modules | `~/.config/bbot/secrets.yml` | Additional recon data sources |
| AWS credentials | `aws configure --profile <name>` | Cloud audit tier (contracted only) |

## 6. First run

```bash
cd bb-agent
claude
```

```
# Verify setup
/stats

# Scout for programs
/find-programs

# Ingest your first program
/program-load https://hackerone.com/your-target

# See what hunts to run
/route your-target

# Run a hunt
/hunt-secrets your-target
```

## 7. Codex (alternative runtime)

bb-agent also works in [OpenAI Codex](https://learn.chatgpt.com/docs/agent-configuration/agents-md). Open this repository in Codex — `AGENTS.md` loads automatically. Use natural language or `Run <command> <args>`:

```
Run stats
Run route my-target
Run hunt-secrets my-target
```

See [docs/codex.md](docs/codex.md) for the full Codex runtime mapping.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `bb_stats.py` fails with "No such file" | Run `bash scripts/bootstrap.sh` to create `memory/` |
| httpx not found / wrong httpx | Ensure ProjectDiscovery httpx is on PATH, not Python httpx |
| Burp MCP tools not available | Restart Claude Code after adding MCP config; check Burp extension is running |
| waymore hangs | Known Wayback CDX issue — the timeout guard handles it; gau covers the gap |
| `theHarvester` aborts on google/bing | Use only: `-b duckduckgo,crtsh,certspotter,dnsdumpster` |
| PMapper import error on Python 3.12 | Patch `from collections import Mapping` → `from collections.abc import Mapping, MutableMapping` |
| nuclei template download fails | Run `nuclei -update-templates` manually first |
