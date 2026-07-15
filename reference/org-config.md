# Org profile — `.ai-data-security.yml`

An **optional** per-repo file that adapts the audit to one organization's vocabulary.
It lives at the root of the *audited* repo (next to `.ai-data-security-ignore`) and is
auto-discovered by the evaluator scripts; `--org-config <path>` overrides the location.

Design rules (enforced by the scripts):

- **Extends only.** The profile can add detection (extra PII tokens, extra citations)
  and provide defaults; it can never remove a builtin pattern, lower a tier floor,
  suppress a finding (that is the ignore file's job), or change a verdict.
- **Zero-config identical.** With no profile present, every script's output is
  byte-identical to pre-profile behavior.
- **Fail closed.** A present-but-unparseable profile is surfaced as a DC-03 / DB-06
  UNKNOWN ("org extensions were NOT applied") — never silently ignored.
- **JSON-formatted.** Parsed with the stdlib `json` module (valid JSON is valid YAML;
  same convention as `reference/citations.yml`), keeping the plugin stdlib-only.
- **Tokens are identifiers.** Classification tokens must match `[A-Za-z0-9_-]{1,64}`;
  anything else is skipped, so a config line can never inject regex syntax.

## Shape

```json
{
  "classification": {
    "filename_restricted":   ["loan_tape", "payroll_extract"],
    "filename_confidential": ["borrower"],
    "column_restricted":     ["payoff_uid", "bank_account_ref"],
    "column_confidential":   ["member_ref", "applicant_name"]
  },
  "warehouse": {
    "dialect": "snowflake",
    "connection": "my_connection_name",
    "role": "AI_AGENT",
    "database": "ANALYTICS"
  },
  "citations": [
    { "display": "Acme Data Governance Policy §4 (PII handling)", "checks": ["DC-01", "DC-02", "DB-03"] }
  ]
}
```

All keys are optional.

## Who reads what

| Key | Consumer | Effect |
|---|---|---|
| `classification.*` | `classify_hints.py` | Extra filename substrings / column-name tokens (token-boundary, like the builtins in [four-tier-framework.md](four-tier-framework.md)) at the named floor |
| `classification.column_*` | db-access-audit SQL packs | The skill compiles the tokens into the `org_restricted` / `org_confidential` regex variables the pack queries accept (`(^|_)(tok1|tok2)(_|$)`); pass `(^|_)(__none__)(_|$)` when unset |
| `warehouse.*` | db-access-audit skill | Argument defaults only — the human gate and `--principal-confirmed` rules are unchanged; explicit arguments always win |
| `citations` | `classify_hints.py`, `eval_grants.py` | Appended to matching findings' citations (after the verified `citations.yml` entries — org citations are the org's own authority, not verified by this repo) |

Secrets never go in this file; it is committed alongside the audited repo.
