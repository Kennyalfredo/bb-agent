#!/usr/bin/env python3
"""bb-agent metrics rollup.

Deterministic aggregation over engagement state so the pipeline's yield, FP,
and disposition health are visible in one command instead of a manual audit.

Read-only. Touches:
  memory/programs/*.json          - programs ingested
  memory/submissions/*.json       - drafted/submitted reports + platform_outcome
  memory/ownership-cache/*.json   - ownership verdicts
  memory/rules.json               - learned rules (filter vs discovery, confidence)
  out/*/                          - engagements executed

Usage:
  python3 scripts/bb_stats.py            # full rollup, human-readable
  python3 scripts/bb_stats.py --json     # machine-readable
"""
import json
import os
import sys
import glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _engine_for(entry):
    """Map a report entry to the engine that produced it."""
    ac = (entry.get("asset_class") or "").lower()
    ft = (entry.get("finding_type") or "").lower()
    if "takeover" in ft:
        return "takeover_hunter"
    if "exposed-internal-tool" in ft or "exposed-endpoint" in ft or "endpoint" in ft:
        return "endpoint_hunter"
    if ac in ("bucket", "bucket_name") or "bucket" in ft:
        return "bucket_hunter"
    if ac == "leaked-credential" or "employee-credential" in ft or "breach" in ft:
        return "footprint/breach"
    if ac in ("secret", "github_org") or "secret" in ft or "credential" in ft:
        return "secret_hunter"
    return "other"


def _disposition_for(entry):
    """Resolve a single normalized disposition string for a report entry."""
    po = entry.get("platform_outcome")
    if isinstance(po, dict) and po.get("disposition"):
        disp = po["disposition"]
        validity = (po.get("validity") or "").upper()
        if disp == "duplicate" and "VALID" in validity:
            return "duplicate (accepted-valid)"
        return disp
    # bc-seek style: a free-text outcome + submitted:false
    if entry.get("outcome"):
        return entry["outcome"]
    if entry.get("submitted") is True:
        return "pending (awaiting triage)"
    if entry.get("submitted") is False:
        return "held (not submitted)"
    return "unknown"


def collect_submissions():
    rows = []
    for path in sorted(glob.glob(os.path.join(ROOT, "memory/submissions/*.json"))):
        d = _load(path)
        if not d:
            continue
        slug = d.get("slug", os.path.basename(path)[:-5])
        entries = d.get("drafts") or d.get("audit_trail") or []
        for e in entries:
            if not isinstance(e, dict):
                continue
            rows.append({
                "slug": slug,
                "asset": e.get("asset"),
                "engine": _engine_for(e),
                "submitted": bool(e.get("submitted")) or "submitted_at" in e,
                "disposition": _disposition_for(e),
                "severity": e.get("severity_capped") or e.get("severity_drafted") or e.get("severity_proposed"),
            })
    return rows


def collect_ownership():
    counts = {"owned": 0, "unknown": 0, "unowned": 0, "other": 0}
    for path in glob.glob(os.path.join(ROOT, "memory/ownership-cache/*.json")):
        d = _load(path)
        if not d:
            continue
        v = d.get("verdict", "other")
        counts[v] = counts.get(v, 0) + 1
    return counts


# rule-type classification: keyword buckets on the rule id / key.
DISCOVERY_KW = ("override", "derivation", "priority", "supplement", "scan",
                "positive_proof", "routing", "required")
FILTER_KW = ("skip", "ignore", "recheck", "refine", "gate", "downweight",
             "basename", "duplicate_prior", "low_impact", "no_speculative",
             "severity_cap", "ban", "fingerprint_required", "ceiling")


def _walk_rules(obj, agent, out):
    if isinstance(obj, dict):
        rid = obj.get("id")
        if isinstance(rid, str) and rid.startswith("rule-"):
            out.append({
                "id": rid,
                "agent": agent,
                "enabled": obj.get("enabled", True) is not False,
                "confidence": obj.get("confidence", "unset"),
                "disabled": "disabled" in obj or obj.get("enabled") is False,
                "ground_truth": bool(obj.get("grounding"))
                or bool(obj.get("validated_against_disposition"))
                or "GROUND TRUTH" in (obj.get("reason", "") or ""),
            })
        for k, v in obj.items():
            _walk_rules(v, agent, out)
    elif isinstance(obj, list):
        for it in obj:
            _walk_rules(it, agent, out)


def classify_rule(rid):
    base = rid
    # filter keywords win when both present (skip/ignore are decisive prunes)
    for kw in FILTER_KW:
        if kw in base:
            return "filter"
    for kw in DISCOVERY_KW:
        if kw in base:
            return "discovery"
    return "other"


def collect_rules():
    d = _load(os.path.join(ROOT, "memory/rules.json")) or {}
    rules = []
    for agent, section in d.items():
        if agent in ("schema_version", "description"):
            continue
        _walk_rules(section, agent, rules)
    return rules


def main():
    as_json = "--json" in sys.argv

    programs = glob.glob(os.path.join(ROOT, "memory/programs/*.json"))
    engagements = [p for p in glob.glob(os.path.join(ROOT, "out/*/"))
                   if os.path.basename(p.rstrip("/")) not in ("scout", "_shared")]
    subs = collect_submissions()
    own = collect_ownership()
    rules = collect_rules()
    proposals = glob.glob(os.path.join(ROOT, "memory/lessons/proposals/*.json"))

    submitted = [r for r in subs if r["submitted"]]
    resolved = [r for r in submitted if r["disposition"] not in
                ("pending (awaiting triage)",) and "pending" not in r["disposition"]]
    # disposition tally over submitted
    disp_tally = {}
    for r in submitted:
        disp_tally[r["disposition"]] = disp_tally.get(r["disposition"], 0) + 1
    # per-engine: drafted + submitted + accepted/valid
    engines = {}
    for r in subs:
        e = engines.setdefault(r["engine"], {"drafted": 0, "submitted": 0,
                                             "rejected": 0, "accepted_or_valid": 0})
        e["drafted"] += 1
        if r["submitted"]:
            e["submitted"] += 1
        d = r["disposition"]
        if d in ("not_applicable", "informative") or "fp" in d.lower() or "withdrawn" in d.lower():
            e["rejected"] += 1
        if "valid" in d.lower() or d in ("resolved", "rewarded", "triaged"):
            e["accepted_or_valid"] += 1
        if d == "duplicate":  # plain duplicate = rejected-ish (no bounty, our finding moot)
            e["rejected"] += 1

    # rules
    rule_class = {"filter": 0, "discovery": 0, "other": 0}
    by_agent = {}
    conf = {}
    disabled = 0
    ground_truth = 0
    for r in rules:
        c = classify_rule(r["id"])
        rule_class[c] += 1
        by_agent[r["agent"]] = by_agent.get(r["agent"], 0) + 1
        conf[r["confidence"]] = conf.get(r["confidence"], 0) + 1
        if r["disabled"]:
            disabled += 1
        if r["ground_truth"] and not r["disabled"]:
            ground_truth += 1

    report = {
        "funnel": {
            "programs_ingested": len(programs),
            "engagements_executed": len(engagements),
            "reports_drafted": len(subs),
            "reports_submitted": len(submitted),
            "dispositions_recorded": len(resolved),
        },
        "dispositions": disp_tally,
        "per_engine": engines,
        "ownership_cache": own,
        "rules": {
            "total": len(rules),
            "enabled": len(rules) - disabled,
            "disabled": disabled,
            "filter": rule_class["filter"],
            "discovery": rule_class["discovery"],
            "other": rule_class["other"],
            "filter_to_discovery_ratio": round(
                rule_class["filter"] / rule_class["discovery"], 1)
            if rule_class["discovery"] else None,
            "ground_truth_validated": ground_truth,
            "by_confidence": conf,
            "by_agent": by_agent,
        },
        "retro_proposals_on_disk": len(proposals),
    }

    if as_json:
        print(json.dumps(report, indent=2))
        return

    def hdr(t):
        print("\n" + t)
        print("-" * len(t))

    print("=" * 60)
    print(" bb-agent metrics rollup")
    print("=" * 60)

    hdr("FUNNEL")
    f = report["funnel"]
    print(f"  programs ingested      {f['programs_ingested']}")
    print(f"  engagements executed   {f['engagements_executed']}")
    print(f"  reports drafted        {f['reports_drafted']}")
    print(f"  reports submitted      {f['reports_submitted']}")
    print(f"  dispositions recorded  {f['dispositions_recorded']}"
          f"  ({f['reports_submitted'] - f['dispositions_recorded']} still pending)")

    hdr("DISPOSITIONS (of submitted)")
    if disp_tally:
        for d, n in sorted(disp_tally.items(), key=lambda x: -x[1]):
            print(f"  {n:>3}  {d}")
    else:
        print("  (none)")

    hdr("PER-ENGINE (drafted / submitted / rejected / accepted-or-valid)")
    for e, s in sorted(engines.items(), key=lambda x: -x[1]["drafted"]):
        print(f"  {e:<18} {s['drafted']:>2} / {s['submitted']:>2} / "
              f"{s['rejected']:>2} / {s['accepted_or_valid']:>2}")

    hdr("OWNERSHIP CACHE")
    for v in ("owned", "unknown", "unowned"):
        print(f"  {v:<9} {own.get(v, 0)}")

    hdr("RULES")
    r = report["rules"]
    print(f"  total {r['total']}  (enabled {r['enabled']}, disabled {r['disabled']})")
    print(f"  filter {r['filter']}  vs  discovery {r['discovery']}  "
          f"(ratio {r['filter_to_discovery_ratio']}:1)")
    print(f"  ground-truth-validated (enabled, high/triager-grounded): {r['ground_truth_validated']}")
    print(f"  by confidence: " + ", ".join(f"{k}={v}" for k, v in sorted(r['by_confidence'].items())))
    print(f"  by agent: " + ", ".join(f"{k}={v}" for k, v in sorted(r['by_agent'].items(), key=lambda x: -x[1])))

    print(f"\n  retro proposals on disk (unapplied or applied): {report['retro_proposals_on_disk']}")
    print()


if __name__ == "__main__":
    main()
