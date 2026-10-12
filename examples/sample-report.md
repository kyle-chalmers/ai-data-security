# Sample report: quick-check

This is real, unedited output from `quick-check` (only the absolute path in the first line was
shortened). The target is `tests/fixtures/ai-config`, a deliberately insecure project that ships
with the plugin's tests: agent settings with no deny rules, MCP servers with credential-shaped
values, unpinned packages, and write-capable warehouse connections. It holds no real data or
credentials. The run was on a machine without gitleaks, so you can also see what a check that
cannot run looks like.

To reproduce it, see lane A in [docs/getting-started.md](../docs/getting-started.md#a-see-a-report-first).
Inside Claude Code, `/ai-data-security:quick-check` shows the same lines and adds a few
sentences on what to do first.

```text
ai-data-security quick-check — tests/fixtures/ai-config (2.0s)

1. Secrets: UNKNOWN — gitleaks unavailable or the scan failed (see UNKNOWN list).
2. Agent config: deny rules missing (AC-01); sandbox filesystem isolation off (AC-07); 17 other finding(s). Retention tier always UNKNOWN (AC-06).
     AC-03 x4  Credential-shaped literal value in an MCP server config
     AC-09 x3  MCP server runs an unpinned package (npx/uvx/@latest/mutable ref)
     AC-10 x3  Warehouse MCP server is write-capable by its own configuration (or its config could not be found → UNKNOWN)
     AC-11 x3  Local sensitive sinks: DuckDB persistent secrets, credential-shaped literals in warehouse CLI configs, shell history without a deny rule
     AC-02 x2  Allow rule grants arbitrary execution via an env-runner wildcard
     AC-04 x1  MCP server configured with trust:true (bypasses tool-call confirmations)
     AC-08 x1  Private data sources and external channels both configured (capability inventory; INFO)
3. Data: 1 Restricted-tier file(s) (DC-01), 1 Confidential-tier (DC-02). Counts only, never values.

UNKNOWN (6):
  - SS-01: quick-check scans the working tree only; git history was not scanned. → Run /ai-data-security:secrets-scanner to cover history and pushed remotes (SS-01/SS-04).
  - SS-05: gitleaks is not installed; quick-check does not substitute a weaker scanner. → brew install gitleaks (or https://github.com/gitleaks/gitleaks/releases), then re-run.
  - AC-06: The consumer 'Help improve Claude' training toggle and retention tier are account settings, not local files — they cannot be audited from this machine. → Check https://claude.ai/settings/data-privacy-controls now. Consumer plans: training ON means 5-year retention (30-day when off; the Aug 2025 rollout pre-set it ON). Team/Enterprise/API accounts are not trained on by default and retain for 30 days; Zero Data Retention is a qualified-Enterprise option. If you handle Confidential/Restricted data with AI tools, verify the tier in writing.
  - AC-10: Toolbox MCP server 'toolbox' (.mcp.json): 1 tool statement(s) could not be classified as read or write by the static matcher (set-path). → Review those statements by hand; only SELECT statements belong in an agent's toolbox.
  - AC-10: Postgres MCP server 'postgres-mcp-remote' (.mcp.json) is remote (URL/SSE) or has no local launch command; its --access-mode is set on the server side and cannot be read here. → Confirm the server runs with --access-mode=restricted where it is launched.
  - DB-06: quick-check does not connect to a warehouse. → Run /ai-data-security:db-access-audit (or security-audit --db) for grants, PII columns, masking, audit logging.

What the codes mean (full list: docs/glossary.md):
  AC-01  Missing recommended secret deny rules in project Claude settings
  AC-07  Bash sandbox not enabled (deny rules bind the tool layer only)
  AC-06  Consumer retention/training tier is not locally auditable (always UNKNOWN)
  DC-01  Restricted-tier file on disk (validated SSN, card, or IBAN content, or a Restricted column or file name)
  DC-02  Confidential-tier file on disk (validated email, phone, or IP content, or a Confidential column or file name)
  SS-01  Secret present in git history (local only)
  SS-05  Secrets scan could not run (gitleaks unavailable or scan error)
  DB-06  DB audit could not run or principal unconfirmed (UNKNOWN / confidence cap)

Findings above pass through from the evaluators with citations and fingerprints; run the full skills for the rendered report.
```

## How to read it

**The three numbered lines are the verdicts.** Each one covers a lane: secrets, agent
configuration, and data files.

- **Line 1, Secrets: UNKNOWN.** gitleaks was not installed, so the plugin did not guess. It
  reported the lane as UNKNOWN and put the install command in the UNKNOWN list (`SS-05`). With
  gitleaks installed, this line reports how many secrets on disk an agent could read.
- **Line 2, Agent config.** No deny rules protect secret files (`AC-01`), and the Bash sandbox is
  off (`AC-07`), so nothing stops a script the agent runs from reading anything on disk. The
  indented rows break the other 17 findings down by check, most frequent first.
- **Line 3, Data.** One file is Restricted (`DC-01`): a stored DuckDB credential in the pretend
  home folder, flagged by its name with `probable` confidence. Another holds a validated email
  address, which makes it Confidential (`DC-02`). The report gives counts only and never repeats
  the values.

**The UNKNOWN list is what the run could not check, and why.** Every entry ends with what would
make it checkable. Three are permanent for quick-check: it never scans git history (`SS-01`),
never connects to a warehouse (`DB-06`), and cannot read your Claude account's retention setting
(`AC-06`). The two `AC-10` entries are different: the check ran but found configs it cannot
classify safely, so it hands them to you instead of guessing.

**"What the codes mean"** gives the plain title for every code the output used. The full list
is in the [glossary](../docs/glossary.md).

## What you would do first

1. Add the deny rules and turn on the sandbox. The `ai-config-audit` report gives the exact
   settings block to paste.
2. Deny the agent access to the stored credential (or remove it if it is no longer used), and
   take the email address out of `opencode.json`.
3. Install gitleaks and run `/ai-data-security:security-audit .` for the full report, which
   covers git history and adds the top five actions.
