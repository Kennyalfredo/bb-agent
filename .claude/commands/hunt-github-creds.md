---
description: "Systematic GitHub credential OSINT sweep for a domain. Runs compound credential-pattern searches that domain-only queries miss. Use for any OSINT engagement before declaring GitHub search complete."
argument-hint: "<domain> [--subdomains az,auth,sso] [--orgs orgname]"
---

# GitHub Credential Sweep

You are running a systematic GitHub credential sweep for: $ARGUMENTS

## MANDATORY — Why this exists

This command exists because domain-only GitHub searches (`"target.com"`) bury credential hits
under noise (domain lists, Alexa datasets, SECURITY.md files). Compound searches like
`"az.target.com"` or `"target.com" password` cut straight to the exposure.

**Lesson:** On a prior engagement, a 13-year-old vendor credential leak in a public test repo
was missed because only domain-only searches were run. See [[feedback-compound-credential-search]].

## Step 1 — Parse arguments

Extract:
- `domain` (required): the target domain
- `--subdomains` (optional): comma-separated auth subdomains to search. If not provided, check if
  CT log data or crt.sh results exist for this domain in `out/` and extract auth-pattern subdomains
  (az, auth, sso, api, login, identity, adfs, federation, iam, oauth).
- `--orgs` (optional): GitHub org names. If not provided, try to derive from domain (strip TLD).
- `--out` (optional): output directory. Default: `out/<slug>/osint/`

## Step 2 — Run the automated sweep

```bash
python3 scripts/gh_credential_sweep.py <domain> \
  --subdomains <comma-list> \
  --orgs <comma-list> \
  --out <output-dir>
```

This runs 5 phases:
1. **Domain-only baseline** — `"domain.com"` (for reference)
2. **Compound credential patterns** — domain + 16 credential keywords (password, secret, token, api_key, oauth, bearer, etc.)
3. **Auth subdomain pivots** — `"sub.domain.com"` for each discovered auth subdomain
4. **Sensitive filename patterns** — domain + filename:.env, config.json, credentials, etc.
5. **Cloud key prefixes** — domain + AKIA, AIza, sk-, xox, ghp_, etc.
6. **Org-specific** — `org:<name> "password"`, `org:<name> "secret"`, etc.

## Step 3 — Triage results

For EACH non-noise result:

1. **Open the repo** — read the actual file content with WebFetch on the raw GitHub URL
2. **Classify** the result:
   - `CREDENTIAL` — actual username/password, API key, token, or secret value visible
   - `ENDPOINT` — auth endpoint, internal URL, or infrastructure reference (no cred but useful)
   - `IDENTITY` — employee email, name, or organizational reference
   - `NOISE` — domain list, dataset, unrelated mention
3. **For CREDENTIAL hits:**
   - Record: type, value (redacted in notes), repo owner, file, exposure date (earliest commit)
   - Determine: is the repo owned by the target, a vendor/partner, or unrelated?
   - Flag for TruffleHog deep scan: `trufflehog git https://github.com/<repo> --only-verified`
4. **For ENDPOINT hits:**
   - Cross-reference with CT log data if available
   - Note if endpoint reveals auth architecture

## Step 4 — Deep scan promising repos

For any repo with CREDENTIAL hits, run:

```bash
# Clone and scan with TruffleHog
trufflehog git https://github.com/<owner>/<repo> --only-verified --json

# If TruffleHog not available, scan commit history manually
gh api repos/<owner>/<repo>/commits --paginate --jq '.[].sha' | head -20
# Then check each commit's diff for credential patterns
```

## Step 5 — Report

Add findings to the engagement's OSINT report. For each credential finding, include:
- Repository URL
- File path
- Credential type and redacted value
- Auth endpoint referenced
- Exposure date (first commit containing the credential)
- Repo owner relationship (employee, vendor, unrelated)
- Risk assessment

## Step 6 — Completeness check

Before declaring GitHub OSINT complete, verify ALL of these were run:

- [ ] Domain-only search
- [ ] At least 6 compound credential searches (password, secret, token, api_key, oauth, bearer)
- [ ] Auth subdomain searches (if CT/recon data available)
- [ ] Sensitive filename searches (at least .env, config.json, credentials)
- [ ] Cloud key prefix searches (at least AKIA, AIza)
- [ ] Org-specific searches (if org identified)
- [ ] TruffleHog on any repo with credential hits
- [ ] Manual review of top results from each phase

**Do NOT mark GitHub search as complete if any checkbox above is unchecked.**

Report the summary to the user: queries run, hits found, credentials discovered, repos flagged for deep scan.
