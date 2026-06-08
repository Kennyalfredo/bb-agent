#!/usr/bin/env python3
"""Engine-routing by target profile.

The pipeline runs every engine on every target regardless of fit, which feeds
the clean-negative streak: secret-hunter on polished mega-orgs (netflix/valve/
opera/okg/dynatrace/basecamp/marionnaud = 7-deep clean-neg), takeover-hunter
(0 findings ever), etc. This planner reads the program profile + the ACTUAL
historical per-engine yield + soft operator signals and emits a per-engine
RUN / DEPRIORITIZE / SKIP plan with rationale.

Advisory, like /dup-check — it never refuses to run an engine, it tells you
where the expected value is so you spend budget well.

Usage:
  python3 scripts/bb_route.py <slug> \
      [--org-maturity young|mature|unknown] \
      [--prior-run-cleanneg] [--json]
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bb_stats import collect_submissions  # reuse engine/disposition logic


def load_program(slug):
    path = os.path.join(ROOT, f"memory/programs/{slug}.json")
    if not os.path.exists(path):
        sys.exit(f"ERROR: {path} not found. Ingest with /program-load first.")
    with open(path) as f:
        return json.load(f)


def profile(prog):
    scope = prog.get("scope", {}) or {}
    ins = scope.get("in_scope", []) or []
    types = {}
    wildcards = 0
    gh_orgs = set()
    for a in ins:
        if not isinstance(a, dict):
            continue
        t = a.get("type", "?")
        types[t] = types.get(t, 0) + 1
        if t == "wildcard":
            wildcards += 1
        asset = str(a.get("asset", ""))
        if t == "source_code" and "github.com/" in asset:
            org = asset.split("github.com/")[1].split("/")[0]
            if org:
                gh_orgs.add(org)
    web_types = {"domain", "wildcard", "subdomain", "url", "application"}
    has_web = any(types.get(t) for t in web_types)
    non_web_only = bool(ins) and not has_web
    rules = prog.get("rules", {}) or {}
    return {
        "types": types,
        "wildcard_count": wildcards,
        "gh_orgs": sorted(gh_orgs),
        "has_gh_org": bool(gh_orgs),
        "has_web": has_web,
        "non_web_only": non_web_only,
        "bucket_listing_allowed": rules.get("bucket_listing_allowed", True),
        "automated_tools_allowed": rules.get("automated_tools_allowed", False),
        "mass_scanning_allowed": rules.get("mass_scanning_allowed", False),
        "explicit_scanner_ban": rules.get("explicit_scanner_ban", False),
    }


def global_prior():
    """Per-engine accepted/rejected/submitted across all recorded dispositions."""
    rows = collect_submissions()
    prior = {}
    for r in rows:
        e = prior.setdefault(r["engine"], {"submitted": 0, "accepted_or_valid": 0,
                                           "rejected": 0})
        if r["submitted"]:
            e["submitted"] += 1
        d = r["disposition"].lower()
        if "valid" in d or d in ("resolved", "rewarded", "triaged"):
            e["accepted_or_valid"] += 1
        elif d in ("not_applicable", "informative") or "fp" in d or "withdrawn" in d or d == "duplicate":
            e["rejected"] += 1
    return prior


def recommend(p, maturity, prior_cleanneg):
    """Return {engine: (verdict, reason)}."""
    out = {}

    # secret_hunter
    if not p["has_gh_org"]:
        out["secret_hunter"] = ("SKIP",
            "no identifiable program GitHub org in scope (no source_code asset). "
            "Brand-stem org-guessing is historically near-zero yield (cf. marionnaud).")
    elif maturity == "mature" or prior_cleanneg:
        out["secret_hunter"] = ("DEPRIORITIZE",
            f"GH org(s) {p['gh_orgs']} present but target is mature/already-clean — "
            "the polished-mega-org cluster (netflix/valve/opera/okg/dynatrace/basecamp) "
            "returns test-fixture-only hits. Run a shallow Pass A; expect clean-neg.")
    else:
        out["secret_hunter"] = ("RUN",
            f"identifiable GH org(s) {p['gh_orgs']} and not flagged mature — "
            "this is the engine's sweet spot (younger orgs yielded toolsforhumanity, "
            "cloudflare, elastic findings).")

    # bucket_hunter
    if not p["bucket_listing_allowed"]:
        out["bucket_hunter"] = ("SKIP", "bucket_listing_allowed=false in program rules.")
    elif p["has_web"]:
        out["bucket_hunter"] = ("RUN (low expectation)",
            "domain/wildcard assets give derivable bucket names, BUT base rate is low: "
            "~24 s3scanner ACL false-positives corroborated, and listable!=owned "
            "(airtable N/A). Apply the acl_recheck gate AND positive-proof gate; "
            "don't draft without a verified CNAME chain or first-party reference.")
    else:
        out["bucket_hunter"] = ("DEPRIORITIZE",
            "no web assets to derive bucket names from; only brand-stem guesses (squatter-prone).")

    # takeover_hunter
    if p["explicit_scanner_ban"] or not p["automated_tools_allowed"]:
        out["takeover_hunter"] = ("SKIP",
            "automated_tools_allowed=false / scanner ban — subzy + curl liveness probes "
            "against program subdomains are prohibited (refuse_if_explicit_scanner_ban). "
            "Also: 0 accepted findings across all engagements to date.")
    elif p["wildcard_count"] >= 5:
        out["takeover_hunter"] = ("DEPRIORITIZE",
            f"{p['wildcard_count']} wildcards = wide surface, the only profile where takeover "
            "is worth it — BUT run TARGETED per-seed passes with RELAXED caps (the 100-sub "
            "cap truncated exactly the surface findings live on, cf. flutteruki betfair/paddypower). "
            "0 accepted findings historically; treat as exploratory.")
    else:
        out["takeover_hunter"] = ("SKIP",
            f"only {p['wildcard_count']} wildcard(s) = narrow surface, and the engine has "
            "0 accepted findings ever (1 FP). Not worth the budget on a narrow target.")

    # endpoint_hunter
    if p["has_web"]:
        out["endpoint_hunter"] = ("RUN",
            "web/wildcard assets present — this is the highest-yield engine on disposition "
            "quality (the only ACCEPTED-as-valid finding: bc-chime flashpaper). Prioritize.")
    else:
        out["endpoint_hunter"] = ("DEPRIORITIZE",
            "no web assets in scope (mobile/source_code/executable only); little for gau to surface.")

    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("slug")
    ap.add_argument("--org-maturity", choices=["young", "mature", "unknown"], default="unknown")
    ap.add_argument("--prior-run-cleanneg", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    prog = load_program(args.slug)
    p = profile(prog)
    prior = global_prior()
    rec = recommend(p, args.org_maturity, args.prior_run_cleanneg)

    if args.json:
        print(json.dumps({"slug": args.slug, "profile": p,
                          "global_prior": prior, "plan": rec}, indent=2))
        return

    order = {"RUN": 0, "RUN (low expectation)": 1, "DEPRIORITIZE": 2, "SKIP": 3}
    print("=" * 60)
    print(f" engine-routing plan — {args.slug}")
    print("=" * 60)
    print(f"  profile: {p['wildcard_count']} wildcards | "
          f"GH org={p['gh_orgs'] or 'none'} | web={p['has_web']} | "
          f"maturity={args.org_maturity}{' | PRIOR CLEAN-NEG' if args.prior_run_cleanneg else ''}")
    print(f"  caps: automated_tools={p['automated_tools_allowed']} "
          f"mass_scanning={p['mass_scanning_allowed']} "
          f"bucket_listing={p['bucket_listing_allowed']}")
    print()
    for eng, (verdict, reason) in sorted(rec.items(), key=lambda kv: order.get(kv[1][0], 9)):
        pr = prior.get(eng, {})
        prline = (f"  [hist: {pr.get('accepted_or_valid',0)} valid / "
                  f"{pr.get('rejected',0)} rejected / {pr.get('submitted',0)} submitted]"
                  if pr else "  [hist: none]")
        print(f"  {verdict:<20} {eng}")
        print(f"    {reason}")
        print(prline + "\n")
    print("  Advisory only — adjust for the specific program. Pass --org-maturity")
    print("  and --prior-run-cleanneg to sharpen the secret-hunter call.")


if __name__ == "__main__":
    main()
