#!/usr/bin/env bash
# Delivery gate (PreToolUse Write|Edit): enforce the internal-pentest coverage checklist.
# - BLOCKS authoring an internal-pentest Typst report if its coverage-checklist.md is missing.
# - WARNS (allows) if the checklist exists but still has bare `[ ]` (unmarked) items.
# Only gates files matching reports/typst/*<interno|internal>*.typ ; everything else passes.
# See methodology/internal-network-pentest-checklist.md + [[reference-internal-pentest-checklist]].

input="$(cat)"
fp="$(printf '%s' "$input" | jq -r '.tool_input.file_path // empty' 2>/dev/null)"
[ -z "$fp" ] && exit 0

# Gate only INTERNAL pentest report .typ files
printf '%s' "$fp" | grep -qiE 'reports/typst/[^/]*(interno|internal)[^/]*\.typ$' || exit 0

# Derive slug + repo root from the path (.../out/<slug>/reports/...)
slug="$(printf '%s' "$fp" | sed -nE 's#.*out/([^/]+)/reports/.*#\1#p')"
[ -z "$slug" ] && exit 0
case "$fp" in
  */out/*) base="${fp%%/out/*}/out/$slug/internal" ;;
  out/*)   base="out/$slug/internal" ;;
  *)       exit 0 ;;
esac

shopt -s nullglob
checklists=("$base"/*/coverage-checklist.md)

if [ ${#checklists[@]} -eq 0 ]; then
  reason="Informe interno BLOQUEADO: falta el coverage-checklist de '$slug' ($base/<ts>/coverage-checklist.md). Corre /coverage-checklist $slug, marca cada item, y reintenta. Enforcement de cobertura — playbook Fase 4/5."
  jq -cn --arg r "$reason" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
fi

bare=0
for f in "${checklists[@]}"; do
  n="$(grep -cE '^- \[ \]' "$f" 2>/dev/null)"
  [ -n "$n" ] && bare=$((bare + n))
done

if [ "$bare" -gt 0 ]; then
  jq -cn --arg s "$slug" --argjson b "$bare" \
    '{systemMessage:("⚠️ coverage-checklist de "+$s+": "+($b|tostring)+" item(s) [ ] sin marcar — complétalos o justifícalos ([B]/[N/A]) antes de entregar."),
      hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"allow",permissionDecisionReason:("Checklist presente; "+($b|tostring)+" item(s) [ ] pendientes (no bloqueante).")}}'
  exit 0
fi

# present + fully marked → allow silently
exit 0
