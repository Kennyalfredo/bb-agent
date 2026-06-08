#!/usr/bin/env python3
"""Record a platform disposition into memory/submissions/<slug>.json.

Deterministic, schema-tolerant JSON mutation. The LLM extracts the disposition
fields from the pasted triager verdict and composes the lesson; this script
just locates the right report entry and writes a standardized `platform_outcome`
block, refusing to clobber an existing one unless --force.

Usage:
  python3 scripts/bb_outcome.py --slug <slug> \
      (--report-id <id> | --asset <asset>) \
      --outcome-json '<json object>' [--force]

The --outcome-json object should follow this shape (only `disposition` is
required; include whatever the verdict gives you):
  {
    "disposition": "duplicate|not_applicable|informative|resolved|rewarded|withdrawn|out_of_scope|spam",
    "validity": "ACCEPTED_AS_VALID_ISSUE",      # optional, for accepted-but-duplicate
    "duplicate_of": "<id>",                       # optional
    "original_disposition": "informative",        # optional (dup-of-informative chains)
    "closed_by": "<triager handle>",              # optional
    "closed_at": "<ISO ts or date>",              # optional
    "triager_reason_verbatim": "...",             # optional but strongly preferred
    "reward_usd": 0,                               # optional
    "captured_at": "<YYYY-MM-DD>",                # required by convention
    "lesson": "..."                                # required by convention
  }
"""
import argparse
import json
import sys

VALID_DISP = {"duplicate", "not_applicable", "informative", "resolved",
              "rewarded", "triaged", "withdrawn", "out_of_scope", "spam",
              "pending", "needs_more_info"}


def find_entries(doc):
    """Return the list that holds report entries (drafts | audit_trail)."""
    for key in ("drafts", "audit_trail"):
        if isinstance(doc.get(key), list):
            return doc[key], key
    return None, None


def match(entry, report_id, asset):
    if report_id:
        for k in ("platform_report_id", "h1_report_id", "report_id"):
            if str(entry.get(k, "")) == str(report_id):
                return True
        url = entry.get("submission_url") or entry.get("h1_report_url") or ""
        if report_id in url:
            return True
        return False
    if asset:
        return entry.get("asset") == asset
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--slug", required=True)
    ap.add_argument("--report-id")
    ap.add_argument("--asset")
    ap.add_argument("--outcome-json", required=True)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    if not args.report_id and not args.asset:
        sys.exit("ERROR: pass --report-id or --asset to locate the entry.")

    path = f"memory/submissions/{args.slug}.json"
    try:
        with open(path) as f:
            doc = json.load(f)
    except FileNotFoundError:
        sys.exit(f"ERROR: {path} not found. Was this finding ever drafted/submitted?")

    try:
        outcome = json.loads(args.outcome_json)
    except json.JSONDecodeError as e:
        sys.exit(f"ERROR: --outcome-json is not valid JSON: {e}")

    disp = outcome.get("disposition")
    if disp not in VALID_DISP:
        sys.exit(f"ERROR: disposition '{disp}' not in {sorted(VALID_DISP)}")
    if not outcome.get("captured_at"):
        sys.exit("ERROR: outcome must include captured_at (YYYY-MM-DD).")
    if not outcome.get("lesson"):
        sys.exit("ERROR: outcome must include a lesson (what the loop learns).")

    entries, key = find_entries(doc)
    if entries is None:
        sys.exit(f"ERROR: {path} has neither 'drafts' nor 'audit_trail' array.")

    hits = [e for e in entries if match(e, args.report_id, args.asset)]
    if not hits:
        ids = [e.get("platform_report_id") or e.get("h1_report_id") or e.get("asset")
               for e in entries]
        sys.exit(f"ERROR: no entry matched. Entries in {path}: {ids}")
    if len(hits) > 1:
        sys.exit(f"ERROR: {len(hits)} entries matched; narrow with --asset.")

    entry = hits[0]
    if entry.get("platform_outcome") and not args.force:
        sys.exit("ERROR: entry already has platform_outcome; pass --force to overwrite.")

    entry["platform_outcome"] = outcome
    # keep a human-readable state field in sync when one exists
    state = {
        "not_applicable": "CLOSED_NOT_APPLICABLE",
        "duplicate": "CLOSED_DUPLICATE",
        "informative": "CLOSED_INFORMATIVE",
        "resolved": "RESOLVED",
        "rewarded": "RESOLVED_REWARDED",
        "out_of_scope": "CLOSED_OUT_OF_SCOPE",
        "spam": "CLOSED_SPAM",
        "withdrawn": "WITHDRAWN",
    }.get(disp)
    if state and "submission_state" in entry:
        entry["submission_state"] = state

    with open(path, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")

    print(f"OK: recorded platform_outcome on {args.slug} / "
          f"{entry.get('asset')} ({entry.get('platform_report_id') or args.report_id}) "
          f"-> {disp}")
    print(f"    submission_state -> {entry.get('submission_state', '(none)')}")


if __name__ == "__main__":
    main()
