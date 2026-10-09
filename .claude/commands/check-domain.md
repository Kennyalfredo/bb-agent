---
description: Check the legitimacy of a domain and the company/entity behind it. Performs DNS, WHOIS, SSL, CT logs, web presence, Wayback, business directory, and email security analysis. Returns a scored verdict (legitimate/suspicious/fraudulent/dormant).
argument-hint: <domain> [optional: "Company Name"]
allowed-tools: Agent
---

You are running a **domain legitimacy check** for: $ARGUMENTS

Parse the arguments:
- First token = domain (strip scheme/path if present, lowercase).
- Remaining tokens (if any, especially if quoted) = company name hint.

Examples:
- `/check-domain 3rdrockelectrical.com` → domain=`3rdrockelectrical.com`, company_hint=null
- `/check-domain example.com "Acme Corp"` → domain=`example.com`, company_hint=`Acme Corp`
- `/check-domain https://sketchy-site.io` → domain=`sketchy-site.io`, company_hint=null

## Orchestration

Delegate to the `domain-legitimacy-checker` subagent. Pass the domain and company hint (if provided).

When the subagent returns, present results to the user in this format:

### Summary
- **Domain**: `<domain>`
- **Verdict**: `<verdict>` (confidence: `<score>`/36 — `<pct>`%)
- **One-liner**: <the summary from the JSON>

### Signal Breakdown
| Check | Score | Weight | Note |
|-------|-------|--------|------|
| Domain age | ... | 2 | ... |
| SSL/TLS | ... | 3 | ... |
| CT history | ... | 2 | ... |
| Web presence | ... | 3 | ... |
| WHOIS | ... | 1 | ... |
| Email security | ... | 2 | ... |
| Wayback history | ... | 2 | ... |
| Business directories | ... | 2 | ... |
| MX records | ... | 1 | ... |

### Red Flags
(bulleted, from the JSON — or "None detected")

### Green Flags
(bulleted, from the JSON — or "None detected")

### Recommendations
(bulleted, from the JSON)

### Output
Full analysis: `<path to JSON>`

If the user provided context about WHY they're checking (e.g. "I got an email from them", "vendor vetting"), tailor the recommendations to that context.
