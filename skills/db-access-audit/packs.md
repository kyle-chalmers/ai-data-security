# Running each pack

The per-dialect detail behind [SKILL.md](SKILL.md) steps 1 to 4: what to state at the gate, how to
capture, and how to evaluate. Read only the section for the dialect being audited. Interpretation
rules (what each output means and which check it feeds) are in [reference.md](reference.md).

Every dialect shares these rules:

- Capture into a `mktemp -d` folder. Any query failure makes that section `DB-06` UNKNOWN (fail
  closed, never a pass); keep going with the rest.
- Pass `--principal-confirmed` to the evaluator ONLY if the user confirmed gate step 2(b);
  otherwise verdicts cap at MEDIUM/possible by design.
- `--ignore-dir` locates the `.ai-data-security-ignore` to honor (and auto-discovers the org
  profile next to it): the current project root for live runs, or the `--recorded` directory in
  air-gapped mode.
- Never fabricate an input. A missing or malformed file is a DB-06 UNKNOWN that names the capture
  command.

## Recorded mode (`--recorded <dir>`)

Instead of connecting, read previously captured query outputs from `<dir>`. No connection and no
gate step 2(a), because nothing touches a database, but principal confirmation 2(b) still
applies. This is how locked-down environments use the skill (a DBA captures outputs, the analyst
audits them), and how the non-Postgres fixtures are validated.

- **postgres / snowflake**: one file per pack query, named after it: `grants`, `pii_columns`,
  `masked_views`, `audit_logging`, `ai_principals`, plus the optional v0.4+ inputs `identity`,
  `policy_attachment` (Postgres) or `policy_references` (Snowflake), `external_paths`,
  `audit_quality`, and `columns` (Postgres). Postgres outputs are `.csv`; Snowflake outputs are
  the `snow sql` `.txt` tables.
- **every other dialect**: one `<file>.csv` per pack file, plus the JSON and manifest files its
  `sql/<dialect>/README.md` lists.

## postgres

**Gate:** every query runs under `default_transaction_read_only=on`. The auditing login must be
able to see the AI role's grants: the AI role itself, a member of it, or a superuser. Without that
standing `grants.csv` comes back empty or partial; `identity.sql` records the auditor's standing
and the evaluator then reports a DB-06 "Grant visibility partial" instead of a clean DB-01/02/03/07.
Say so, and ask which login the connection uses before confirming.

**Capture:** for each pack file:
`PGOPTIONS='-c default_transaction_read_only=on' psql "<connection>" --csv -q -v ON_ERROR_STOP=1 -v ai_role='<role>' -v org_restricted='<regex>' -v org_confidential='<regex>' -f <file> > <tmp>/<name>.csv`

The Postgres pack has ten files (`identity`, `policy_attachment`, `external_paths`,
`audit_quality` since v0.4; `columns` since v0.6, which feeds the planner and produces no
finding); all run under the same read-only PGOPTIONS.

**Evaluate** (also used for snowflake):

```
python3 "${CLAUDE_PLUGIN_ROOT}/skills/db-access-audit/scripts/eval_grants.py" \
  --dialect <postgres|snowflake> \
  --grants <tmp>/grants.<csv|txt> --pii <tmp>/pii_columns.<csv|txt> \
  --views <tmp>/masked_views.<csv|txt> --settings <tmp>/audit_logging.<csv|txt> \
  --identity <tmp>/identity.<csv|txt> \
  --policies <tmp>/policy_attachment.csv|<tmp>/policy_references.txt \
  --external <tmp>/external_paths.csv --audit-quality <tmp>/audit_quality.<csv|txt> \
  --columns <tmp>/columns.csv \
  --role <role> [--principal-confirmed] --ignore-dir <dir> --emit-json <tmp>/eval.json
```

The v0.4 inputs (`--identity`, `--policies`, `--external`, `--audit-quality`) are optional: leave
one out (or point at a file whose query failed) and the script reports that check as DB-06
UNKNOWN with the statement to capture.

## snowflake

**Gate:** `policy_references.sql` needs
`GRANT DATABASE ROLE SNOWFLAKE.GOVERNANCE_VIEWER TO ROLE <the role your connection uses>` and
`audit_quality.sql` needs `SNOWFLAKE.SECURITY_VIEWER` (both read `SNOWFLAKE.ACCOUNT_USAGE`, up
to 120 minutes behind). Say plainly that without them DB-08/DB-09 will be reported UNKNOWN,
not clear; never ask the user to run the audit as ACCOUNTADMIN.

**Capture:** See [reference.md](reference.md) for the per-file `snow sql` invocations
(pii_columns.sql additionally takes `-D "org_restricted=..."` / `-D "org_confidential=..."`;
`identity.sql` and `audit_quality.sql` take `-D "user=<ai-user>"`; `policy_references.sql`
takes `-D "db=..."`) and output capture; Snowflake support is fixture-validated (no live CI
account) — say so in the report header.

**Evaluate:** the postgres command above with `--dialect snowflake` and the `.txt` files. Pass the
captured `snow sql` output files as-is; the script parses the ASCII tables and applies the
reference.md interpretation rules mechanically.

## databricks

`--role` is the AI principal exactly as Unity Catalog names it: a
service principal's applicationId (UUID), a user's email, or a group name; `--catalog` is the
catalog to audit. Validate them (`--catalog` against `^[A-Za-z0-9_-]+$`, `--role` against
`^[A-Za-z0-9_.@+-]+$`; refuse anything else — they are substituted into SQL), derive
`principal_kind` (`GROUP` when the principal is neither an email nor a UUID, else `USER`),
substitute all three into each pack file, and capture CSV with the user's pre-authenticated
Databricks SQL CLI, passing the SQL as text (never via a pipe into `$(cat)`):
`dbsqlcli --table-format csv -e "$(sed -e "s/\${catalog}/<catalog>/g" -e "s/\${principal}/<principal>/g" -e "s/\${principal_kind}/<USER|GROUP>/g" sql/databricks/<file>.sql)" > <tmp>/<file>.csv`.
Gate preconditions to state: INFORMATION_SCHEMA shows a viewer only its own grants unless it
owns the securable or is a metastore admin, and `SHOW GROUPS WITH USER` needs administrator
privileges, so the capture must run as the catalog owner or a metastore admin; otherwise
grants are partial and the report says so. There is no
session-level read-only switch; the CI lint on `sql/databricks/` is the guarantee.

## redshift

Redshift speaks the PostgreSQL protocol: run each file in
`sql/redshift/` through the user's own `psql` (port 5439) exactly like the Postgres pack but
with `-v ai_user='<the database user the agent connects as>'` (IAM-auth users are named
`IAM:<name>` / `IAMA:<name>`); `--role` is that user name. There is no `PGOPTIONS` read-only
switch on Redshift; the CI lint on `sql/redshift/` is the guarantee. Gate preconditions to
state: relation grants of OTHER identities are visible only to superusers or `SYSLOG ACCESS
UNRESTRICTED`; role/user grants and schema privileges need `ACCESS SYSTEM TABLE`; the masking
and RLS attachment views return ZERO rows to anyone but superusers and `sys:secadmin` — so the
capture should run as a superuser or a `sys:secadmin` + `sys:monitor` holder, and the report
says when it did not (identity.sql records the auditor's standing).

## bigquery (partial by design)

`--role` is the IAM member string exactly as
bindings spell it (`serviceAccount:<email>`, `user:<email>`, `group:<email>`); `--project`,
`--region` (e.g. `us`), `--dataset` are validated (`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`,
`^[a-z0-9-]+$`, `^[A-Za-z0-9_]+$`) and substituted. `sql/bigquery/README.md` gives the exact
`bq` / `gcloud` capture loop: OBJECT_PRIVILEGES must be queried per dataset and per table
(`grants_dataset.sql`, `grants_table.sql` → one `grants.csv`), plus JSON captures
`iam_policy.json` (project IAM: the inherited access OBJECT_PRIVILEGES never shows),
`deny_policies.json`, `log_bucket.json`, `row_access_policies.json`, `sa_keys.json` (service
accounts only), a `tables_manifest.csv` from `bq ls` (so the evaluator can prove the per-table
loop completed), and a `policy_tags.csv` (policy tags AND data policies, nested fields
included) built from `bq show --schema`. Run the loop under `set -euo pipefail`. Gate
preconditions to state: OBJECT_PRIVILEGES needs `bigquery.datasets.get` /
`bigquery.tables.getIamPolicy`; `get-iam-policy` needs `resourcemanager.projects.getIamPolicy`;
JOBS needs `bigquery.jobs.listAll` AND `bigquery.jobs.create`. Say plainly that
folder/organization bindings, principal access boundaries, Google Group / domain / principal-set
membership, custom-role permissions, conditional bindings, authorized views, and Fine-Grained
Reader / data-policy IAM are NOT captured and appear as UNKNOWNs; basic roles (Owner / Editor /
Viewer) are identity breadth, not table access.

## fabric (partial by design)

`--role` is the database principal name as
`sys.database_principals` spells it (an Entra user's UPN, a service principal's display name,
or an Entra group name); validate `^[A-Za-z0-9._@ -]{1,128}$` (no quotes, semicolons, or `--`) and substitute
`${principal}` only where the pack documents it. Capture each `sql/fabric/*.sql` with the
user's own `sqlcmd -G` against the SQL connection string (port 1433, Entra only, no SQL
auth): `sqlcmd -S <endpoint> -d <warehouse> -G -i <file>.sql -s "," -W -h -1 -f 65001 -o <tmp>/<file>.csv`
(each file emits its own header row; eight files incl. `ownership` and `modules`), plus the
optional `audit_status.json` (Fabric REST `settings/sqlAudit`) and `endpoint_mode.json`
(`{"itemType": "Warehouse"}`, or a lakehouse SQL analytics endpoint's `accessMode`; in
user-identity mode SQL grants are ignored and every table-access verdict is UNKNOWN). Gate preconditions to state: SQL GRANT/DENY is HALF the
model — workspace Admin/Member/Contributor hold CONTROL (read and write everything, unmasked)
and Viewer holds ReadData on every table; item permissions (Read/ReadData/ReadAll) grant access
outside SQL; none of that is visible from T-SQL, so the report says so on every finding.
`sys.database_permissions` shows other principals only with VIEW DEFINITION / ALTER ANY USER:
capture as a workspace Admin or Member.

## lakeformation (partial by design, no SQL)

`--role` is the IAM principal ARN
exactly as Lake Formation spells it (`arn:aws:iam::<acct>:role/<name>`, `:user/<name>`, a
SAML or Identity Center ARN); validate `^arn:aws:[a-z0-9-]+::?[0-9]*:[A-Za-z0-9:/_.@+=,-]+$`.
Capture the JSON files listed in `sql/lakeformation/README.md` with the user's own AWS CLI
(`list-permissions` for the principal AND for everyone, `get-data-lake-settings`,
`list-data-cells-filter`, `glue get-tables` per database merged with
`jq -s '{TableList: [.[].TableList[]]}'`, `list-resources`, `iam list-attached-role-policies`;
plus `list-lake-formation-opt-ins` when any location is in hybrid access mode and
`cloudtrail describe-trails` for DB-05). Gate preconditions to state: `list-permissions` returns
explicitly granted permissions only; LF-tag-based and conditional grants are not resolved (DB-06);
grants to `IAMAllowedPrincipals` / `ALLIAMPrincipals` hand control to IAM; whether the
principal's IAM policies read S3 directly is judged by AWS-managed policy NAME only (inline,
customer and group policies, boundaries, SCPs, bucket policies → DB-06); Athena / Redshift
Spectrum query text is not in CloudTrail.

## duckdb (posture pack)

There are no roles: whoever opens the file
holds every privilege. `--role` is the OS user (or `local`). Capture with the user's own
`duckdb -readonly -csv -header <file> < sql/duckdb/<q>.sql` for the six queries, plus the
`stat` line with the `git_ignore` column as `sql/duckdb/README.md` shows. Gate preconditions to
state: settings reflect the CAPTURE session, not the agent's process (the agent must set the
guards itself, then `lock_configuration`); MotherDuck (`md:`) controls are not verified.

## Evaluating databricks, redshift, bigquery, fabric, lakeformation, and duckdb

```
python3 "${CLAUDE_PLUGIN_ROOT}/skills/db-access-audit/scripts/eval_grants.py" --dialect <dialect> \
  --recorded <tmp> --role <principal> [--principal-confirmed] --ignore-dir <dir> --emit-json <tmp>/eval.json
```

One `<file>.csv` per pack file; a missing or malformed file is a DB-06 UNKNOWN naming the capture
command.

The safe-db-access planner has templates for postgres and snowflake only; for these dialects say
so when offering next steps.
