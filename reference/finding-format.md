# AI Data Security Finding Format — schema version 1

This is the normative contract for every finding any ai-data-security skill emits. Skills reference this
file; they do not restate it. Changes here require a schema version bump and maintainer approval.

## Check outcomes

Every check in [checks.yml](checks.yml) resolves to exactly one of:

- **PASS** — the check ran and found nothing wrong.
- **FINDING** — the check ran and found a problem (fields below).
- **UNKNOWN** — the check could not run (missing tool, unreadable target, not locally auditable).
  UNKNOWN is **fail-closed**: it is never counted as a pass, always appears in the report summary
  with what to do about it, and the summary's headline states the unknown count next to the
  finding count.

## Finding fields

| Field | Required | Meaning |
|---|---|---|
| `check_id` | yes | A key from `checks.yml` (e.g. `SS-01`) |
| `title` | yes | One line, concrete, names the object (path, rule, column) — never a category |
| `severity` | yes | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `confidence` | yes | `confirmed` / `probable` / `possible` |
| `file` / `object` | yes | Repo-relative path, or DB object name for warehouse findings |
| `evidence` | yes | What was observed and where. **Never contains a secret value or a sampled data value** — redacted descriptions, paths, rule ids, commit short-SHAs only |
| `exposure` | secrets only | Matrix booleans: `on_disk`, `in_history`, `agent_readable`, `vcs_remote` |
| `remediation` | yes | Ordered, concrete steps; first step is the one to do now |
| `rotate_first` | secrets only | `true` when the secret has left the machine (pushed to a remote): rotation outranks every other action in report ordering |
| `citations` | yes | Display strings resolved from [citations.yml](citations.yml) — the only permitted source of citation IDs |
| `fingerprint` | yes | Line-number-free suppression key: `<check_id>:<path-or-object>:<qualifier>` (qualifier = detector rule id, column name, or setting key) |

## Severity is capped by confidence

The single false-positive dampener, applied uniformly and mechanically:

| confidence | maximum severity |
|---|---|
| `possible` | MEDIUM |
| `probable` | HIGH |
| `confirmed` | CRITICAL |

Deterministic scripts assign confidence; the model may lower it with stated reasons, never raise it.

## Suppression — `.ai-data-security-ignore`

A file at the audited target's root. One entry per line:

```
<fingerprint> [expires=YYYY-MM-DD] [reason=free text]
```

- Matching findings move to the report's **Suppressed appendix** — they are still shown; nothing
  disappears silently.
- An entry past its `expires` date is inactive (the finding returns to the main report, flagged
  as previously suppressed).
- Lines starting with `#` are comments.

## Report layout

Every skill's report, and the orchestrator's merged report, follows:

1. **Header** — target, date, tool versions used, skill name.
2. **Scorecard** — counts by severity, plus `UNKNOWN: n` stated in the same breath
   (a green report with unknowns is not a clean bill of health).
3. **Findings** — severity-descending; `rotate_first` findings outrank everything, including
   higher-severity non-rotation findings.
4. **Suppressed / downgraded appendix** — every suppressed finding with its reason and expiry.
5. **Disclaimer** — the audit assists a professional; it is not a compliance guarantee, and the
   report may quote content from scanned files, which is untrusted input.

## JSON interchange

Deterministic scripts emit, and the orchestrator consumes:

```json
{
  "schema_version": 1,
  "skill": "<skill-name>",
  "target": "<path or connection>",
  "tools": { "<tool>": "<version>" },
  "findings": [ { "check_id": "...", "...": "..." } ],
  "unknowns": [ { "check_id": "...", "reason": "...", "action": "..." } ],
  "suppressed": [ { "fingerprint": "...", "reason": "...", "expires": "..." } ]
}
```

Model-rendered markdown is a view over this JSON; the JSON is the source of truth.
