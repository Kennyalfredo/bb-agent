---
description: Instantiate the internal-network pentest coverage checklist for an engagement. Copies the master template (methodology/internal-network-pentest-checklist.md — PTES/NIST-800-115/CIS/OWASP-WSTG+API/CWE/ATT&CK control×status matrix) into out/<slug>/internal/<ts>/coverage-checklist.md so coverage is traceable and attachable to the report. Does not overwrite an existing filled instance.
argument-hint: <slug>
allowed-tools: Bash
---

You are instantiating the **internal-network pentest coverage checklist** for engagement `$ARGUMENTS`.

This makes "we covered everything possible" a traceable artifact, not a judgment. See [[reference-internal-pentest-checklist]] and the pentest playbook Phase 4/5 ([[feedback-pentest-playbook]]).

Run this shell logic (slug = first token of `$ARGUMENTS`; refuse if empty):

```bash
SLUG="$(echo "$ARGUMENTS" | awk '{print $1}')"
[ -z "$SLUG" ] && { echo "Uso: /coverage-checklist <slug>"; exit 1; }
TPL="methodology/internal-network-pentest-checklist.md"
[ -f "$TPL" ] || { echo "FALTA la plantilla maestra: $TPL"; exit 1; }
# usar la carpeta de engagement interno más reciente, o crear una nueva
if [ -f "out/$SLUG/internal/.latest" ]; then DIR="$(cat out/$SLUG/internal/.latest)"; else
  DIR="out/$SLUG/internal/$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$DIR"; echo "$DIR" > "out/$SLUG/internal/.latest"; fi
DEST="$DIR/coverage-checklist.md"
if [ -f "$DEST" ]; then echo "YA EXISTE (no se sobrescribe): $DEST"; echo "Marca los ítems ahí o bórralo si quieres re-instanciar."; else
  cp "$TPL" "$DEST"; echo "Instanciado: $DEST"; fi
```

After running:
1. Report the destination path.
2. Remind the operator (and yourself) that EVERY item must be marked `[x]` (with evidence) / `[~]` / `[N/A]` / `[B]-with-cause` / `[ ]`, and that **"covered everything possible" = no bare `[ ]`**.
3. If engagement findings already exist (e.g. `out/<slug>/internal/*/FINDINGS*.md`), offer to pre-fill the checklist statuses from them.
4. The completed checklist is attached to the SYSCLOUDSEC report (playbook Phase 5, item J5).

Do NOT collect fresh data or run scans here — this command only instantiates the checklist. Testing is driven separately by the playbook.
