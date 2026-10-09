#!/usr/bin/env python3
"""
gh_credential_sweep.py — Systematic GitHub credential OSINT for a target domain.

Runs compound credential-pattern searches that domain-only queries miss.
Born from a missed vendor credential leak on a prior engagement (13yr-old cred in a public repo).

Usage:
    python3 scripts/gh_credential_sweep.py target.com [--subdomains sub1,sub2,sub3]
    python3 scripts/gh_credential_sweep.py target.com --subdomains az,auth,sso,api --out out/slug/osint/

Output: JSON + human-readable summary to stdout and optional --out directory.
"""

import subprocess
import json
import sys
import os
import argparse
import time
from datetime import datetime, timezone
from collections import defaultdict

QUERY_DELAY_SECONDS = 3  # GitHub code search: 10 req/min for authenticated users

CREDENTIAL_PATTERNS = [
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "client_secret",
    "oauth",
    "bearer",
    "authorization",
    "private_key",
    "access_key",
    "BEGIN RSA",
    "BEGIN PRIVATE",
    "jdbc:",
    "mongodb+srv",
    "smtp",
    "ftp://",
]

SENSITIVE_FILENAMES = [
    ".env",
    ".env.production",
    ".env.local",
    "config.json",
    "config.yml",
    "config.yaml",
    "credentials",
    "credentials.json",
    "docker-compose.yml",
    "docker-compose.yaml",
    "application.properties",
    "application.yml",
    "appsettings.json",
    "appsettings.Development.json",
    ".npmrc",
    ".netrc",
    ".htpasswd",
    "id_rsa",
    "id_ed25519",
    "wp-config.php",
    "settings.py",
    "secrets.yml",
    "vault.yml",
    "terraform.tfvars",
    ".tfstate",
]

CLOUD_KEY_PATTERNS = [
    "AKIA",           # AWS access key prefix
    "ASIA",           # AWS STS key prefix
    "AIza",           # Google API key prefix
    "sk-",            # OpenAI / Stripe key prefix
    "xox",            # Slack token prefix
    "ghp_",           # GitHub PAT prefix
    "glpat-",         # GitLab PAT prefix
    "sq0",            # Square key prefix
]


def run_gh_search(query, limit=30):
    """Run gh search code and return raw output lines."""
    cmd = ["gh", "search", "code", query, "--limit", str(limit)]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return [], result.stderr.strip()
        lines = [l for l in result.stdout.strip().split("\n") if l.strip()]
        return lines, None
    except subprocess.TimeoutExpired:
        return [], "TIMEOUT"
    except Exception as e:
        return [], str(e)


def parse_result_line(line):
    """Parse a gh search code result line into repo:file and snippet."""
    parts = line.split("\t") if "\t" in line else line.split(None, 1)
    if len(parts) >= 2:
        return parts[0].strip(), parts[1].strip()
    return line.strip(), ""


def dedupe_key(repo_file):
    """Normalize repo:file for deduplication."""
    return repo_file.lower().strip()


def is_noise(repo_file, snippet):
    """Filter known noise patterns."""
    noise_repos = [
        "cirosantilli/expired-domain",
        "alexatop1m",
        "phishing_url",
        "hiddentreasure",
        "privadb",
        "randomwebsite",
        "blocklist",
        "domain-database",
        "top-1m",
        "brantas-judol",
        "deep-learning-of-dga",
    ]
    rf_lower = repo_file.lower()
    for noise in noise_repos:
        if noise in rf_lower:
            return True
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Systematic GitHub credential OSINT sweep"
    )
    parser.add_argument("domain", help="Target domain (e.g. target.com)")
    parser.add_argument(
        "--subdomains",
        default="",
        help="Comma-separated auth subdomains to search (e.g. az,auth,sso,api,login)",
    )
    parser.add_argument(
        "--orgs",
        default="",
        help="Comma-separated GitHub org names to search (e.g. targetorg,target-inc)",
    )
    parser.add_argument(
        "--out",
        default="",
        help="Output directory for JSON results",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=30,
        help="Max results per query (default 30)",
    )
    args = parser.parse_args()

    domain = args.domain
    subdomains = [s.strip() for s in args.subdomains.split(",") if s.strip()]
    orgs = [o.strip() for o in args.orgs.split(",") if o.strip()]
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    all_results = []
    seen = set()
    stats = {
        "domain": domain,
        "timestamp": ts,
        "queries_run": 0,
        "queries_with_hits": 0,
        "total_raw_results": 0,
        "total_deduped_results": 0,
        "total_after_noise_filter": 0,
        "errors": [],
    }
    findings_by_category = defaultdict(list)

    query_count = [0]  # mutable counter for closure

    def search_and_collect(query, category):
        if query_count[0] > 0:
            time.sleep(QUERY_DELAY_SECONDS)
        query_count[0] += 1
        stats["queries_run"] += 1
        lines, err = run_gh_search(query, args.limit)
        if err:
            if "rate limit" in err.lower():
                print(f"  [{category}] RATE LIMITED — waiting 60s...", file=sys.stderr)
                time.sleep(60)
                lines, err = run_gh_search(query, args.limit)
            if err:
                stats["errors"].append({"query": query, "error": err})
                print(f"  [{category}] ERROR: {err}", file=sys.stderr)
                return

        stats["total_raw_results"] += len(lines)
        hits = 0
        for line in lines:
            repo_file, snippet = parse_result_line(line)
            dk = dedupe_key(repo_file)
            if dk in seen:
                continue
            seen.add(dk)
            stats["total_deduped_results"] += 1

            if is_noise(repo_file, snippet):
                continue
            stats["total_after_noise_filter"] += 1
            hits += 1

            entry = {
                "repo_file": repo_file,
                "snippet": snippet,
                "query": query,
                "category": category,
            }
            all_results.append(entry)
            findings_by_category[category].append(entry)

        if hits > 0:
            stats["queries_with_hits"] += 1
        status = f"{hits} hit(s)" if hits else "clean"
        print(f"  [{category}] {query!r} → {status}")

    # === PHASE 1: Domain-only (baseline) ===
    print(f"\n{'='*60}")
    print(f"PHASE 1: Domain-only baseline — {domain}")
    print(f"{'='*60}")
    search_and_collect(f'"{domain}"', "domain-baseline")

    # === PHASE 2: Compound credential patterns ===
    print(f"\n{'='*60}")
    print(f"PHASE 2: Compound credential patterns — {domain}")
    print(f"{'='*60}")
    for pattern in CREDENTIAL_PATTERNS:
        search_and_collect(f'"{domain}" {pattern}', f"compound-{pattern}")

    # === PHASE 3: Subdomain-specific searches ===
    if subdomains:
        print(f"\n{'='*60}")
        print(f"PHASE 3: Auth subdomain pivots")
        print(f"{'='*60}")
        for sub in subdomains:
            fqdn = f"{sub}.{domain}"
            search_and_collect(f'"{fqdn}"', f"subdomain-{sub}")

    # === PHASE 4: Sensitive filename patterns ===
    print(f"\n{'='*60}")
    print(f"PHASE 4: Sensitive filename patterns — {domain}")
    print(f"{'='*60}")
    for fname in SENSITIVE_FILENAMES[:10]:  # top 10 to stay under rate limits
        search_and_collect(
            f'"{domain}" filename:{fname}', f"filename-{fname}"
        )

    # === PHASE 5: Cloud key prefix patterns ===
    print(f"\n{'='*60}")
    print(f"PHASE 5: Cloud key prefixes — {domain}")
    print(f"{'='*60}")
    for prefix in CLOUD_KEY_PATTERNS:
        search_and_collect(f'"{domain}" "{prefix}"', f"cloud-key-{prefix}")

    # === PHASE 6: Org-specific searches ===
    if orgs:
        print(f"\n{'='*60}")
        print(f"PHASE 6: Org-specific credential searches")
        print(f"{'='*60}")
        for org in orgs:
            for pattern in ["password", "secret", "token", "BEGIN RSA", "AKIA"]:
                search_and_collect(
                    f'org:{org} "{pattern}"', f"org-{org}-{pattern}"
                )

    # === SUMMARY ===
    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"Domain:              {domain}")
    print(f"Queries run:         {stats['queries_run']}")
    print(f"Queries with hits:   {stats['queries_with_hits']}")
    print(f"Raw results:         {stats['total_raw_results']}")
    print(f"After dedup:         {stats['total_deduped_results']}")
    print(f"After noise filter:  {stats['total_after_noise_filter']}")
    print(f"Errors:              {len(stats['errors'])}")

    if findings_by_category:
        print(f"\nFindings by category:")
        for cat, entries in sorted(findings_by_category.items()):
            print(f"  {cat}: {len(entries)}")
            for e in entries[:3]:
                print(f"    → {e['repo_file']}")
            if len(entries) > 3:
                print(f"    ... and {len(entries)-3} more")

    if stats["errors"]:
        print(f"\nErrors:")
        for e in stats["errors"][:5]:
            print(f"  {e['query']}: {e['error']}")

    # === WRITE OUTPUT ===
    output = {
        "meta": stats,
        "results": all_results,
    }

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        outfile = os.path.join(args.out, f"gh-credential-sweep-{ts}.json")
        with open(outfile, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\nResults written to: {outfile}")
    else:
        print(
            f"\nTip: use --out out/<slug>/osint/ to save results to a file"
        )

    # === NEXT STEPS ===
    print(f"\n{'='*60}")
    print("NEXT STEPS (manual review required)")
    print(f"{'='*60}")
    print("1. Review each hit — is the repo owned by target, a vendor, or unrelated?")
    print("2. For credential hits: check if creds are current or historical")
    print("3. For vendor repos: check if they expose target's auth endpoints/secrets")
    print("4. Run TruffleHog on promising repos:")
    print("   trufflehog git https://github.com/<repo> --only-verified")
    print("5. Run noseyparker for historical scan:")
    print("   noseyparker scan --git-url https://github.com/<repo>")
    print(f"6. Search auth subdomains found via CT logs:")
    print(f"   python3 scripts/gh_credential_sweep.py {domain} --subdomains az,auth,sso,api,login")

    return 0 if stats["total_after_noise_filter"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
