#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m' YELLOW='\033[1;33m' RED='\033[0;31m' BOLD='\033[1m' NC='\033[0m'
ok()   { printf "  ${GREEN}✓${NC} %s\n" "$1"; }
skip() { printf "  ${YELLOW}–${NC} %s (already exists)\n" "$1"; }
warn() { printf "  ${YELLOW}!${NC} %s\n" "$1"; }
fail() { printf "  ${RED}✗${NC} %s\n" "$1"; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

printf "\n${BOLD}bb-agent bootstrap${NC}\n\n"

# ── 1. memory/ scaffold ─────────────────────────────────────────────
printf "${BOLD}Directory scaffold${NC}\n"
for dir in memory/programs memory/submissions memory/ownership-cache \
           memory/employee-cache memory/lessons/proposals out; do
  if [ -d "$dir" ]; then skip "$dir/"; else mkdir -p "$dir" && ok "$dir/"; fi
done

if [ -f memory/rules.json ]; then
  skip "memory/rules.json"
else
  printf '[]' > memory/rules.json && ok "memory/rules.json"
fi

if [ -f memory/lessons.md ]; then
  skip "memory/lessons.md"
else
  printf '# Lessons\n\nAppended by /retro after each engagement.\n' > memory/lessons.md
  ok "memory/lessons.md"
fi

# ── 2. Off-repo evidence store ───────────────────────────────────────
printf "\n${BOLD}Off-repo evidence store${NC}\n"
EVIDENCE="/mnt/files/bb-agent"
if [ -d "$EVIDENCE" ]; then
  skip "$EVIDENCE/"
elif mkdir -m 0700 "$EVIDENCE" 2>/dev/null; then
  ok "$EVIDENCE/ (mode 0700)"
else
  warn "$EVIDENCE/ could not be created (no write access to /mnt/files)."
  warn "Create it manually or set a different path in your agent playbooks."
fi

# ── 3. Tool check ────────────────────────────────────────────────────
printf "\n${BOLD}Tool inventory${NC}\n"
printf "  %-16s %s\n" "TOOL" "STATUS"
printf "  %-16s %s\n" "────" "──────"

MISSING=0
TOOLS=(trufflehog noseyparker subfinder nuclei httpx dnsx subzy gau gh
       s3scanner amass curl jq dig git aws waymore maigret gowitness)

for tool in "${TOOLS[@]}"; do
  path=$(which "$tool" 2>/dev/null || true)
  if [ -n "$path" ]; then
    printf "  ${GREEN}%-16s${NC} %s\n" "$tool" "$path"
  else
    printf "  ${RED}%-16s${NC} %s\n" "$tool" "not found"
    ((MISSING++)) || true
  fi
done

# ── 4. Claude Code ───────────────────────────────────────────────────
printf "\n${BOLD}Claude Code${NC}\n"
if which claude >/dev/null 2>&1; then
  ok "claude found at $(which claude)"
else
  fail "claude not found — install Claude Code: https://docs.anthropic.com/en/docs/claude-code"
  ((MISSING++)) || true
fi

# ── Summary ──────────────────────────────────────────────────────────
printf "\n${BOLD}Summary${NC}\n"
if [ "$MISSING" -eq 0 ]; then
  ok "All tools present. Run ${BOLD}claude${NC} in the repo root to start."
else
  warn "$MISSING tool(s) missing. See SETUP.md for installation instructions."
  warn "bb-agent works without all tools — missing ones block specific hunters."
fi
printf "\n"
