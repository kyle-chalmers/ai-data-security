---
description: Check what this machine can audit before running anything — detects gitleaks, psql, snow, docker, verifies the plugin's citation registry and evaluator scripts, reports Bash sandbox posture, and prints a capability matrix naming which checks will be UNKNOWN. Read-only; installs nothing.
argument-hint: "[--home <dir>]"
allowed-tools: "Bash(python3 *), Read"
---

# doctor

Run this first. It answers "what will this plugin be able to verify on this machine?" so an
audit never surprises you with UNKNOWNs it could have predicted.

## Steps

1. Run the deterministic probe (it never installs anything and always exits 0):
   ```
   python3 "${CLAUDE_PLUGIN_ROOT}/skills/doctor/scripts/doctor.py" [--home <dir>]
   ```
   Pass `--home` only when `$ARGUMENTS` supplies it (fixtures do); otherwise the real home
   directory is used to read user-scope Claude settings.

2. Show the output as-is: tools present or missing (with versions), the capability matrix per
   skill (`ready` / `partial` / `UNKNOWN` with the reason), registry health, evaluator compile
   status, and sandbox posture. Do not soften a `missing` or `UNKNOWN`.

3. Give the user the one or two commands that change the matrix, in this order of impact:
   - `brew install gitleaks` (or the releases page) if gitleaks is missing — the secrets lane
     fails closed without it, by design. If Betterleaks is present, say it was detected and is
     reported for information only (SPEC design rule 6 names gitleaks as the primary scanner).
   - `"sandbox": {"enabled": true}` in `~/.claude/settings.json` if the sandbox is off (AC-07
     will fire on every audit until it is on).
   - `psql` / Snowflake CLI only if the user plans a live DB audit; `--recorded <dir>` works
     without them.

4. End with the suggested next command: `/ai-data-security:quick-check <path>` for a
   one-minute read, or `/ai-data-security:security-audit <path>` for the full flow.

AC-06 (consumer retention tier) is always UNKNOWN and the doctor says so; it is an account
setting, not a file.
