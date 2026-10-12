# Troubleshooting

Each entry starts from what you see. Run `/ai-data-security:doctor` first if you have not: most
first-run problems are a missing tool, and doctor names it along with the install command.

## Setup

### The `/ai-data-security:` commands don't appear after install

**Cause:** Claude Code loads plugins when a session starts.
**Fix:** Run `/reload-plugins`, or start a new session. Then check `claude plugin list` shows
`ai-data-security`.

### The secrets line says UNKNOWN, or a report lists `SS-05`

**Cause:** gitleaks is not installed, or it failed. The plugin will not swap in a weaker scanner,
so the secrets lane fails closed.
**Fix:** `brew install gitleaks` (or a release from
[github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks/releases)), then re-run.

### A lane timed out in quick-check

**Cause:** Each quick-check evaluator has a 35-second budget. A lane that runs out becomes an UNKNOWN,
never a pass. Very large folders (data dumps, `node_modules`) are the usual reason.
**Fix:** Run the matching full skill (`secrets-scanner`, `ai-config-audit`, or
`data-classification`) on the folder, which has no such budget, or point quick-check at a smaller
path.

## Agent configuration

### `AC-06` is UNKNOWN on every run

**Cause:** By design. Whether your Claude account trains on your data, and how long it keeps
conversations, is an account setting, not a file on your machine.
**Fix:** Check it at [claude.ai/settings/data-privacy-controls](https://claude.ai/settings/data-privacy-controls).
If you handle Confidential or Restricted data with AI tools, get the retention tier in writing.

### I added deny rules but `AC-07` still fires

**Cause:** Deny rules stop the agent's own file tools, not the programs it runs. A `grep -r` or a
script can still read a denied file. AC-07 is about the sandbox, which applies the deny paths to
every subprocess.
**Fix:** Enable the Bash sandbox (`sandbox.enabled: true` in `~/.claude/settings.json`). The
`ai-config-audit` report gives the exact block.

### `AC-10` is UNKNOWN for a Toolbox or Postgres MCP server

**Cause:** Either a Toolbox statement could not be classified as read or write by the static
matcher, or the Postgres MCP server is remote, so its access mode is set where it runs.
**Fix:** Review the named statements by hand (only `SELECT` belongs in an agent's toolbox), or
confirm the remote server runs with `--access-mode=restricted`.

## Warehouse audits

### db-access-audit stopped after showing a summary and ran nothing

**Cause:** That summary is the gate. The skill never queries a database until you confirm the
target and confirm that `--role` is the identity your AI tooling uses.
**Fix:** Reply to confirm both. In a scripted or orchestrated run, pass `--confirm`.

### Every DB finding is capped at MEDIUM, with a `DB-06` about the principal

**Cause:** Nobody confirmed that `--role` is the identity the AI tool connects as, so the audit
cannot claim more than "possible".
**Fix:** Re-run and confirm the principal at the gate.

### Snowflake: `DB-08` or `DB-09` is UNKNOWN

**Cause:** The auditing role cannot read `SNOWFLAKE.ACCOUNT_USAGE` policy and access views.
**Fix:** Have an admin grant `SNOWFLAKE.GOVERNANCE_VIEWER` (for DB-08) and
`SNOWFLAKE.SECURITY_VIEWER` (for DB-09) to the role your `snow` connection uses. Do not run the
audit as ACCOUNTADMIN. These views can lag up to 120 minutes, so a grant made just now may not
show yet.

### Redshift: masking or row-level security checks come back UNKNOWN

**Cause:** Redshift returns zero rows from its masking and RLS attachment views to anyone but a
superuser or a `sys:secadmin` holder. The audit treats an empty answer from a lower-privileged
login as "could not see", never "none attached".
**Fix:** Capture as a superuser, or as a user with `sys:secadmin` and `sys:monitor`.

### Postgres: `DB-06` says "Grant visibility partial" or "unverified"

**Cause:** Postgres only shows a grant to its grantor, to members of the grantee, and to
superusers. The login that ran the capture was none of those for the AI role, so the grants file
came back empty or partial. Without the check, that would have looked like "no grants".
**Fix:** Capture again as the AI role itself, a role that is a member of it, or a superuser, and
include `identity.sql` (it records which login ran the capture). "Unverified" means `identity.sql`
was missing or came from a pack older than v0.13.

### Databricks: the report says grants are partial

**Cause:** Unity Catalog's `INFORMATION_SCHEMA` shows a user only their own grants unless they own
the securable or are a metastore admin.
**Fix:** Run the capture as the catalog owner or a metastore admin. If `dbsqlcli` is not
installed, have someone who has it run the capture and use `--recorded <dir>`.

### Fabric: every table-access verdict is UNKNOWN

**Cause:** The target is a lakehouse SQL analytics endpoint in user-identity mode, where SQL
grants are ignored and access is decided outside SQL, where the audit cannot see.
**Fix:** This is a real limit of what T-SQL can show. Review the lakehouse's item and workspace
permissions in Fabric directly.

### Permission prompts while capturing a BigQuery, Databricks, Lake Formation, or DuckDB pack

**Cause:** The skill pre-approves the read commands each pack documents (`bq query`, `gcloud
projects get-iam-policy`, `aws lakeformation list-*`, `duckdb -readonly`, and so on). The capture
recipes also use shell helpers such as `sed`, `cut`, `git check-ignore`, and loops, and those still
ask, as does the Fabric REST call for `audit_status.json`.
**Fix:** Approve them, or run the capture commands from the pack's README yourself and audit the
output with `--recorded <dir>`.

### A capture file is missing or malformed

**Cause:** One query failed, or one capture step was skipped. The audit reports that section as
`DB-06` UNKNOWN and keeps going with the rest.
**Fix:** The DB-06 finding names the exact capture command. Run it and re-run the audit.

## Fix plans

### safe-db-access says "REFUSED: no reviewed templates exist for dialect ..."

**Cause:** The planner has templates for Postgres and Snowflake only.
**Fix:** For the other warehouses, use the remediation steps in each db-access-audit finding.

### safe-db-access can't find the eval JSON

**Cause:** db-access-audit writes `eval.json` into a temporary folder.
**Fix:** Use the path the audit printed in its closing "Next" line. If that session is gone,
re-run db-access-audit; it is read-only and safe to repeat.

## Results

### A finding I suppressed is back

**Cause:** Its entry in `.ai-data-security-ignore` has an `expires=` date that has passed. The
finding returns to the main report flagged as previously suppressed.
**Fix:** Fix it, or renew the entry with a new date and a reason.

### "extensions were NOT applied" in a report

**Cause:** `.ai-data-security.yml` could not be parsed, so your extra column names were ignored
for this run (reported as `DC-03` or `DB-06`).
**Fix:** The file is JSON despite the `.yml` name. Validate it with `jq . .ai-data-security.yml`
and check every token matches `^[A-Za-z0-9_-]{1,64}$`.
