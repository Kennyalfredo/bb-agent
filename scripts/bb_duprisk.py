#!/usr/bin/env python3
"""Duplicate-likelihood pre-flight scorer.

3 of the first 4 recorded dispositions were DUPLICATES, and they shared one
trait: long public exposure on a prominent target (elastic 12yr secret, chime
3yr archived service, TFH old keys). This scorer turns the signals we can see
PASSIVELY into a duplicate-risk tier so the operator can calibrate effort
before submitting. It is ADVISORY — duplicate-risk is partly unavoidable (we
cannot see other researchers' private reports), so this never hard-blocks.

The caller (the /dup-check command) gathers the signals from the candidate
JSON + optional public-disclosure search and passes them as flags. The scoring
rubric here is deterministic and transparent.

Usage:
  python3 scripts/bb_duprisk.py \
      --exposure-age-days 4502 \
      --archive-indexed \
      --asset-prominence high \
      --finding-class oss_default_exposure \
      --public-disclosure-hits 0 \
      [--test-or-history-path]
"""
import argparse
import json

# transparent additive rubric -> tier
def score(args):
    pts = 0
    factors = []

    d = args.exposure_age_days
    if d is not None:
        if d >= 5 * 365:
            pts += 4; factors.append(f"exposure ~{d}d (>5yr): +4")
        elif d >= 3 * 365:
            pts += 3; factors.append(f"exposure ~{d}d (>3yr): +3")
        elif d >= 547:  # ~1.5yr
            pts += 2; factors.append(f"exposure ~{d}d (>1.5yr): +2")
        elif d >= 182:
            pts += 1; factors.append(f"exposure ~{d}d (>6mo): +1")
        else:
            factors.append(f"exposure ~{d}d (<6mo): +0 (fresh — lower dup-risk)")

    if args.archive_indexed:
        pts += 2; factors.append("the exact finding URL/secret is archive-indexed (Wayback/gau): +2")

    prom = {"high": 2, "medium": 1, "low": 0}.get(args.asset_prominence, 0)
    if prom:
        pts += prom; factors.append(f"asset prominence '{args.asset_prominence}' (flagship repo / primary brand domain): +{prom}")
    else:
        factors.append("asset prominence low/obscure: +0")

    common = {
        "oss_default_exposure": 2,   # e.g. publicly-running open-source tool at default config
        "well_known_repo_secret": 2,  # secret in a flagship/popular repo everyone scans
        "common_misconfig": 1,        # listable bucket, default creds
        "novel": 0,                   # obscure/unusual finding
    }.get(args.finding_class, 0)
    if common:
        pts += common; factors.append(f"finding class '{args.finding_class}' (heavily-scanned pattern): +{common}")
    else:
        factors.append(f"finding class '{args.finding_class}': +0 (less-trodden)")

    if args.public_disclosure_hits and args.public_disclosure_hits > 0:
        pts += 4; factors.append(f"{args.public_disclosure_hits} public/disclosed report(s) on this program reference the same asset/class: +4 (near-certain prior)")

    if args.test_or_history_path:
        pts += 1; factors.append("secret lives in a test/CI fixture or git-history-only path (scanned by everyone): +1")

    if pts >= 7:
        tier = "NEAR-CERTAIN"
    elif pts >= 4:
        tier = "HIGH"
    elif pts >= 2:
        tier = "MEDIUM"
    else:
        tier = "LOW"
    return pts, tier, factors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exposure-age-days", type=int, default=None,
                    help="age of the finding's public exposure (secret first-commit, earliest Wayback snapshot)")
    ap.add_argument("--archive-indexed", action="store_true")
    ap.add_argument("--asset-prominence", choices=["high", "medium", "low"], default="low")
    ap.add_argument("--finding-class",
                    choices=["oss_default_exposure", "well_known_repo_secret",
                             "common_misconfig", "novel"], default="novel")
    ap.add_argument("--public-disclosure-hits", type=int, default=0)
    ap.add_argument("--test-or-history-path", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    pts, tier, factors = score(args)

    advice = {
        "NEAR-CERTAIN": "Almost certainly already reported. Submit only if the finding is novel in some dimension the prior reports likely missed, or skip. Set expectations to duplicate.",
        "HIGH": "Likely a duplicate. Worth submitting only if valid AND the program pays duplicate points (Bugcrowd P1/P2) or you can differentiate it. Don't over-invest in the writeup.",
        "MEDIUM": "Some duplicate-risk. Proceed, but check public disclosures first if you haven't.",
        "LOW": "Low duplicate-risk on passive signals. Proceed.",
    }[tier]

    if args.json:
        print(json.dumps({"points": pts, "tier": tier, "factors": factors,
                          "advice": advice}, indent=2))
        return

    print(f"DUPLICATE-RISK: {tier}  (score {pts})")
    print("factors:")
    for f in factors:
        print(f"  - {f}")
    print(f"advice: {advice}")
    print("NOTE: advisory only — private reports are invisible, so this never hard-blocks.")


if __name__ == "__main__":
    main()
