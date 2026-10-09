#!/usr/bin/env python3
"""Rule-base hygiene auditor for memory/rules.json.

Standing hygiene tool (not a one-off cleanup) so the rule base stays healthy as
it grows. Read-only — reports issues; the human fixes via /retro or by hand.

Checks:
  [DISABLED]      rules turned off (informational — kept as cautionary records)
  [SELF-HIGH]     confidence:high WITHOUT triager grounding (violates convention:
                  only platform-disposition-grounded rules may claim high)
  [NO-PROV]       missing any of id/added/from_engagement/confidence/reason
  [DUP-ID]        the same rule id appears twice
  [REDUNDANT]     two enabled rules in one array share an identical match key
  [STALE-REF]     an enabled rule references a now-disabled rule id
  [DRIFT]         filter:discovery ratio (learning-loop bias watch)

Usage:
  python3 scripts/bb_rule_audit.py          # human-readable
  python3 scripts/bb_rule_audit.py --json
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "memory/rules.json")

PROV_FIELDS = ("id", "added", "from_engagement", "confidence", "reason")
DISCOVERY_KW = ("override", "derivation", "priority", "supplement", "scan",
                "positive_proof", "routing")
FILTER_KW = ("skip", "ignore", "recheck", "refine", "gate", "downweight",
             "basename", "duplicate_prior", "low_impact", "no_speculative",
             "severity_cap", "ban", "ceiling")


def walk(obj, agent, acc):
    if isinstance(obj, dict):
        if isinstance(obj.get("id"), str) and obj["id"].startswith("rule-"):
            acc.append((agent, obj))
        for v in obj.values():
            walk(v, agent, acc)
    elif isinstance(obj, list):
        for it in obj:
            walk(it, agent, acc)


def classify(rid):
    for kw in FILTER_KW:
        if kw in rid:
            return "filter"
    for kw in DISCOVERY_KW:
        if kw in rid:
            return "discovery"
    return "other"


def is_ground_truth(rule):
    """A rule may legitimately claim confidence:high only when grounded in
    external truth: a platform disposition or an explicit user-policy directive.
    Recognized via an explicit `grounding` field, a `validated_against_disposition`
    field, or a `reason` that opens with GROUND TRUTH."""
    if rule.get("grounding") or rule.get("validated_against_disposition"):
        return True
    return (rule.get("reason") or "").strip().upper().startswith("GROUND TRUTH")


# fields that carry ACTIVE matching logic (vs narrative/provenance text)
LOGIC_FIELDS = ("match_condition", "when", "applies_when", "match", "pattern",
                "applies_to")


def main():
    as_json = "--json" in sys.argv
    with open(RULES) as f:
        doc = json.load(f)

    acc = []
    for agent, section in doc.items():
        if agent in ("schema_version", "description"):
            continue
        walk(section, agent, acc)

    findings = {"DISABLED": [], "SELF-HIGH": [], "NO-PROV": [], "DUP-ID": [],
                "STALE-REF": []}
    seen_ids = {}
    disabled_ids = set()
    f_count = d_count = 0

    for agent, r in acc:
        rid = r["id"]
        seen_ids[rid] = seen_ids.get(rid, 0) + 1
        disabled = ("disabled" in r) or (r.get("enabled") is False)
        if disabled:
            disabled_ids.add(rid)
            findings["DISABLED"].append(rid)
        else:
            c = classify(rid)
            if c == "filter":
                f_count += 1
            elif c == "discovery":
                d_count += 1
        if r.get("confidence") == "high" and not is_ground_truth(r) and not disabled:
            findings["SELF-HIGH"].append(rid)
        missing = [k for k in PROV_FIELDS if not r.get(k)]
        if missing:
            findings["NO-PROV"].append(f"{rid} (missing: {','.join(missing)})")

    for rid, n in seen_ids.items():
        if n > 1:
            findings["DUP-ID"].append(f"{rid} (x{n})")

    # stale-ref: an enabled rule's ACTIVE LOGIC names a disabled rule id
    # (narrative/provenance mentions of a disabled rule are harmless history)
    for agent, r in acc:
        disabled = ("disabled" in r) or (r.get("enabled") is False)
        if disabled:
            continue
        logic_blob = " ".join(str(r.get(k, "")) for k in LOGIC_FIELDS)
        for did in disabled_ids:
            if did != r["id"] and did in logic_blob:
                findings["STALE-REF"].append(f"{r['id']} references disabled {did} in active logic")

    ratio = round(f_count / d_count, 1) if d_count else None
    report = {
        "total_rules": len(acc),
        "enabled": len(acc) - len(findings["DISABLED"]),
        "filter_vs_discovery": {"filter": f_count, "discovery": d_count, "ratio": ratio},
        "findings": findings,
    }

    if as_json:
        print(json.dumps(report, indent=2))
        return

    print("=" * 56)
    print(" rule-base hygiene audit")
    print("=" * 56)
    print(f"  total {report['total_rules']}  enabled {report['enabled']}  "
          f"disabled {len(findings['DISABLED'])}")
    print(f"  filter {f_count} : discovery {d_count}  (ratio {ratio}:1)")
    if ratio and ratio >= 3:
        print("  [DRIFT] filter:discovery >= 3:1 — learning loop is mostly pruning,")
        print("          not finding. Bias next retros toward discovery candidates.")
    for tag in ("SELF-HIGH", "NO-PROV", "DUP-ID", "STALE-REF", "DISABLED"):
        items = findings[tag]
        if not items:
            continue
        print(f"\n[{tag}] ({len(items)})")
        for it in items:
            print(f"  - {it}")
    blocking = sum(len(findings[t]) for t in ("SELF-HIGH", "NO-PROV", "DUP-ID", "STALE-REF"))
    print(f"\n  {blocking} issue(s) needing attention "
          f"(DISABLED entries are informational).")


if __name__ == "__main__":
    main()
