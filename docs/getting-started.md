# Getting started

Pick the lane that matches what you want today. Each one ends with the command to run next.

| Lane | You get | Needs | Time |
|---|---|---|---|
| [A. See a report first](#a-see-a-report-first) | A real report on a deliberately insecure sample project | Nothing, or `git` + `python3` to run it yourself | 2 minutes |
| [B. Audit a project folder](#b-audit-a-project-folder) | Secrets, agent config, and sensitive files in your repo | Claude Code, `python3`, gitleaks | 5 to 30 minutes |
| [C. Audit a warehouse](#c-audit-a-warehouse) | What your AI's database login can actually do | Lane B, plus your warehouse CLI and an auditor login | 15 to 45 minutes |

Words in a report you don't recognise are defined in the [glossary](glossary.md). If something
fails, check [troubleshooting](troubleshooting.md).

## A. See a report first

Read [examples/sample-report.md](../examples/sample-report.md). It is the real output of
`quick-check` against a fixture that ships with the plugin's tests, annotated so you can see what
each line means and what you would do about it.

To produce it yourself without installing anything into Claude Code:

```bash
git clone https://github.com/kyle-chalmers/ai-data-security.git
```

```bash
cd ai-data-security && python3 -B skills/quick-check/scripts/quick_check.py --target tests/fixtures/ai-config --home tests/fixtures/ai-config/home
```

`--home` points at the fixture's pretend home folder (sample user settings, warehouse CLI configs,
and shell history), so the demo audits those instead of your real `~/.claude`. In normal use you
leave it out, because your real user settings are part of what gets audited.

Next: lane B on one of your own projects.

## B. Audit a project folder

**1. Install the plugin** (once per machine):

```bash
claude plugin marketplace add kyle-chalmers/ai-data-security
```

```bash
claude plugin install ai-data-security@ai-data-security
```

**2. Install gitleaks** (`brew install gitleaks`, or a release from
[github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks/releases)). It finds the
secrets; this plugin works out who can reach them. Without it the secrets lane reports UNKNOWN
rather than quietly passing.

**3. Check what this machine can audit.** In Claude Code, inside the project:

```
/ai-data-security:doctor
```

It lists which tools are present and, for every skill and warehouse pack, whether it is `ready`,
`partial`, or will come back `UNKNOWN`, and says what would change that (the install command for
gitleaks; for a missing warehouse CLI, that recorded mode still works). It installs nothing and
changes nothing.

**4. Get the one-minute read:**

```
/ai-data-security:quick-check .
```

Three verdict lines (secrets an agent can read, agent permission posture, sensitive file counts)
and a list of everything it could not check. It does not scan git history or connect to a
warehouse, and it says so.

**5. Run the full audit when you have half an hour:**

```
/ai-data-security:security-audit .
```

It runs secrets-scanner (including git history), ai-config-audit, data-classification, and
dbt-governance-audit when a dbt project is present, then merges them into one report with the
top five actions first.

### What Claude can and can't see during an audit

- The bundled Python scripts decide every verdict. Claude reads their JSON and writes the
  report; it cannot change a severity or turn an UNKNOWN into a pass.
- Secret values never reach the report: gitleaks runs with `--redact`, and the evaluators carry
  paths and rule IDs only. Classification reports counts and column names, never values.
- Claude never asks for, prints, or stores a password. Warehouse connections go through the CLI
  you have already signed in to.
- Warehouse queries return metadata only: grants, object and column names, settings. Claude reads
  those results; the packs never select rows from your tables.
- Files, git history, and query results are treated as untrusted text. Instructions hidden in
  them do not override the skills.

The full trust model, including the known limits, is in [SECURITY.md](../SECURITY.md).

## C. Audit a warehouse

`db-access-audit` answers one question: what can the login your AI tool uses actually do? It runs
read-only queries (every one is in `skills/db-access-audit/sql/<dialect>/` and CI-checked for
zero writes) and stops to ask you before it touches the database.

**1. Know your AI principal.** That is the role, user, service principal, or IAM member your AI
tooling connects as. If you are not sure, the skill can run `ai_principals.sql` first to list the
candidates.

**2. Make sure the auditing login can see enough.** The audit runs as *you* (or a DBA), not as the
AI principal, and most warehouses hide other identities' grants from ordinary users. With too
little access the affected checks come back UNKNOWN, never clean.

| Pack (`--dialect`) | CLI you sign in with | Auditing login needs | Coverage |
|---|---|---|---|
| `postgres` | `psql` | A role that can see the AI role's grants: the AI role itself, a member of it, or a superuser | Full |
| `snowflake` | `snow` (a named connection) | `SNOWFLAKE.GOVERNANCE_VIEWER` and `SNOWFLAKE.SECURITY_VIEWER` database roles, for masking and audit-quality checks. Never ACCOUNTADMIN | Full (fixture-validated, no live CI account) |
| `databricks` | `dbsqlcli` | Catalog owner or metastore admin (otherwise grants are partial) | Full, with a standing note on visibility |
| `redshift` | `psql` on port 5439 | Superuser, or `sys:secadmin` + `sys:monitor` (masking and RLS views are empty to anyone else) | Full |
| `bigquery` | `bq` + `gcloud` | `bigquery.datasets.get`, `bigquery.tables.getIamPolicy`, `resourcemanager.projects.getIamPolicy`, `bigquery.jobs.listAll`, `bigquery.jobs.create`, `iam.denypolicies.list` | Partial by design: folder and org IAM, groups, custom roles are UNKNOWN |
| `fabric` | `sqlcmd -G` (Entra sign-in) | Workspace Admin or Member | Partial by design: workspace roles and item permissions are UNKNOWN |
| `lakeformation` | `aws` | Read permission for every Lake Formation, Glue, IAM, and CloudTrail call listed in the pack README | Partial by design: tag-based grants and non-managed IAM policies are UNKNOWN |
| `duckdb` | `duckdb` | Read access to the database file | Posture only: DuckDB has no users or grants |

The capture commands for every pack are in that pack's README under
`skills/db-access-audit/sql/<dialect>/`.

**3. Run it.** For example, Postgres:

```
/ai-data-security:db-access-audit --dialect postgres --connection "host=db.example.com dbname=analytics" --role ai_agent
```

Before any query runs, the skill shows you the target (with any password redacted), the role, the
exact files it will run, and the read-only enforcement. It waits for you to confirm two things:
that it may run them, and that `--role` really is the identity your AI tooling uses. Until you
confirm the second, findings are capped at MEDIUM.

For Snowflake, `--connection` is the name of a connection you have already set up in the Snowflake
CLI, and `--user` is the user the agent signs in as:

```
/ai-data-security:db-access-audit --dialect snowflake --connection my_conn --role AI_ROLE --user AI_AGENT_USER
```

Keep passwords out of `--connection`: use `~/.pgpass`, a `PGSERVICE` entry, or your CLI's saved
connection. If one slips in, the skill redacts it whenever it repeats the target, but it has
still passed through the conversation.

The audit prints where it wrote its results (`eval.json`) at the end; you need that path for the
next step.

**Can't connect from your laptop?** Use recorded mode. A DBA runs the capture commands and hands
you the output folder, and you run the audit with `--recorded <dir>`. Nothing connects.

**4. Get the fix as SQL text.** For Postgres and Snowflake, `db-access-audit` ends by offering:

```
/ai-data-security:safe-db-access --audit <path to eval.json>
```

It prints the least-privilege recipe (a service identity, masked views, revoke raw access, grant
curated access, an audit trail, a validation script, and a rollback) as SQL text for a human to
review and run. It never connects and never executes anything. The other packs report findings
with remediation steps but have no generated recipe yet.

To include the warehouse in the full audit, pass the same arguments to `security-audit`:

```
/ai-data-security:security-audit . --db '--dialect postgres --connection <conninfo> --role <ai-role>'
```

## After your first run

- **A finding you have accepted?** Add its fingerprint to `.ai-data-security-ignore` with a
  reason and an expiry date. It moves to the Suppressed appendix and comes back when the date
  passes.
- **Your own sensitive column names?** Add them to `.ai-data-security.yml`
  ([reference/org-config.md](../reference/org-config.md)).
- **Want results in GitHub?** `security-audit . --sarif results.sarif` writes a file Code
  Scanning can ingest.
