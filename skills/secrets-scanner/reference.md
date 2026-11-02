# secrets-scanner reference

## Why two gitleaks scans

- `gitleaks git` scans **history** — secrets that were ever committed, even if deleted since.
- `gitleaks dir` scans the **working tree as files** — including gitignored files like `.env`,
  which never appear in history but sit on disk where any agent or subprocess can read them.

One scan without the other misses half the exposure story. The eval script merges both by
`(file, rule)` and reports disk exposure and history exposure as separate findings because their
remediations differ (deny rule + relocation vs. history rewrite + rotation).

## Whose rules the scan uses

The scan always uses the plugin's own gitleaks rules, never the scanned repo's. Both scans pass
`--config skills/secrets-scanner/gitleaks/gitleaks.toml`, a config that extends gitleaks' default
rules (`[extend] useDefault = true`) and adds no allowlists. So:

| In the scanned repo | What happens |
|---|---|
| `.gitleaks.toml`, including any allowlist | Ignored. A secret it allowlists is still reported. The report header says the file was not used. |
| An inline `gitleaks:allow` comment | Ignored (`--ignore-gitleaks-allow`). The secret on that line is an ordinary finding at full severity. |
| `.gitleaksignore` | gitleaks always loads this file and cannot be told not to. Each entry is listed in the Suppressed appendix as skipped by the repo, and one `SS-05` UNKNOWN says those locations were not verified. |
| `.ai-data-security-ignore` | Honored. This is the one place for intentional skips, and every one shows in the Suppressed appendix. |

gitleaks' own built-in defaults (for example the documented AWS example key) still apply; they
come with gitleaks, not with the scanned repo. A `.gitleaksignore` in the directory you run from is
not loaded either: `--gitleaks-ignore-path` points at the plugin's `gitleaks/` directory, which
holds none.

### Adding an intentional skip

1. Run the scan and copy the finding's `fingerprint` (for example `SS-03:.env:github-pat`).
2. Add one line to `.ai-data-security-ignore` at the scanned repo's root:
   `SS-03:.env:github-pat expires=2027-01-31 reason=local test token, rotated weekly`
3. Re-run. The finding moves to the Suppressed appendix with its reason and expiry, and returns
   to the main report once the date passes.

Do not add allowlists to a `.gitleaks.toml` or a `.gitleaksignore` for this: the first is ignored,
and the second leaves a location the audit cannot verify.

## The exposure matrix

| Dimension | Question | Common misconception corrected |
|---|---|---|
| `on_disk` | Is the secret in the working tree right now? | ".gitignore protects it" — no; gitignore only keeps it out of *future commits* |
| `in_history` | Was it ever committed? | "I deleted the file" — deletion doesn't remove past commits |
| `agent_readable` | Does any `permissions.deny` Read rule cover the path? | "It's gitignored so the agent won't read it" — agents read the filesystem, not git |
| `vcs_remote` | Is a containing commit on a remote-tracking branch? | "I'll rewrite history" — after a push, rotation is the only safe response |

## Severity ladder (assigned by eval_secrets.py, before confidence capping)

| Check | Condition | Severity | Why |
|---|---|---|---|
| SS-04 | in history AND pushed | CRITICAL + rotate_first | The secret has left the machine; treat as compromised |
| SS-03 | on disk AND no deny rule | CRITICAL | Any AI agent or tool in this repo can read it today |
| SS-02 | on disk, deny rule present | HIGH | Claude Code won't read it, but subprocesses still can |
| SS-01 | local history only | HIGH | One `git push` away from SS-04 |

Confidence: structured-format detector rules (github-pat, aws-access-key-id, private-key, …) are
`confirmed`; entropy-based rules (generic-api-key) are `probable`, which caps severity at HIGH per
finding-format.md. The model may lower confidence with stated reasons, never raise it.

## Optional deeper tools (recommend, don't run by default)

- **trufflehog** — live credential *verification* (is the key active?). AGPL-3.0 and makes network
  calls to credential providers; suggest only as an explicit opt-in follow-up.
- **detect-secrets** — baseline workflow for legacy repos with many known findings. Warn:
  `detect-secrets scan --baseline` is destructive (rewrites the baseline to only scanned paths);
  `detect-secrets-hook` is the safe variant.

## SS-05 manual fixture (`manual-uninstalled-tool`)

CI cannot uninstall gitleaks. Procedure: on a machine without gitleaks (or with PATH temporarily
stripped), invoke the skill against any repo; expected outcome is a report with zero findings,
one UNKNOWN for SS-05 carrying install instructions, and an explicit statement that the scan did
not run — never a clean bill of health.
