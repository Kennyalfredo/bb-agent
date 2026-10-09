#!/usr/bin/env python3
"""Read-only internal-report coverage check for Codex's instruction-driven gate."""

import argparse
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
UNCHECKED = re.compile(r"^\s*[-*+]\s+\[ \]", re.MULTILINE)


def check(root, slug, delivery=False):
    """Return (exit code, messages); never write files or contact targets."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", slug):
        return 2, ["Invalid slug: use a single program name, not a path."]
    base = root / "out" / slug / "internal"
    checklists = sorted(base.glob("*/coverage-checklist.md"))
    if not checklists:
        return 1, [f"BLOCKED: no coverage checklist under {base}/<timestamp>/.",
                   f"Run coverage-checklist {slug} before authoring an internal report."]
    messages = []
    pending = 0
    for path in checklists:
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            return 2, [f"Cannot read {path}: {exc}"]
        if not content.strip():
            return 1, [f"BLOCKED: empty coverage checklist: {path}"]
        count = len(UNCHECKED.findall(content))
        pending += count
        messages.append(f"{path.relative_to(root)}: {count} unchecked item(s)")
    if pending:
        label = "BLOCKED" if delivery else "WARNING"
        messages.append(f"{label}: {pending} unchecked item(s); complete or justify before delivery.")
        return (1 if delivery else 0), messages
    messages.append("PASS: checklists present with no unchecked items; review evidence before delivery.")
    return 0, messages


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("slug", help="Engagement slug in memory/programs")
    parser.add_argument("--delivery", action="store_true",
                        help="Fail on unchecked items before declaring a report ready")
    args = parser.parse_args()
    code, messages = check(ROOT, args.slug, args.delivery)
    print("\n".join(messages))
    return code


if __name__ == "__main__":
    sys.exit(main())
