# db-access-audit reference

## Check map (all dialects)

| Check | Question | Severity (confirmed principal) |
|---|---|---|
| DB-01 | Does the AI principal hold write privileges? | CRITICAL |
| DB-02 | Does it read base tables instead of governed views? | HIGH |
| DB-03 | Are PII-named columns readable unmasked? | HIGH (Restricted floor) / MEDIUM (Confidential floor) |
| DB-04 | Is there any masked/governed view layer at all? | MEDIUM |
| DB-05 | Is there any audit trail of its queries? | MEDIUM |
| DB-06 | Anything the audit could not verify | UNKNOWN (fail-closed) |
| DB-ID-01 | Is the principal's *effective* identity wider than its role? (pg: superuser / BYPASSRLS / CREATEROLE, owned relations, INHERIT memberships; sf: user `TYPE` not SERVICE / SERVICE_AGENT, `DEFAULT_SECONDARY_ROLES = ('ALL')`, extra roles granted to the user) | CRITICAL (super/bypass) / HIGH |
| DB-07 | Is the raw-to-curated boundary crossed by an *indirect* path? (pg: inherited grants, PUBLIC grants, default privileges; sf: USAGE on ROLE = inheritance) | HIGH |
| DB-08 | Is a governed control actually *attached* to the PII columns it can read? (pg: `anon` masking labels, RLS state; sf: `ACCOUNT_USAGE.POLICY_REFERENCES`; dynamic tables refreshing as their owner → INFO) | HIGH |
| DB-09 | How good is the audit trail? (pg: pgaudit loaded and configured, per-role `log_statement`, collector; sf: who holds `GOVERNANCE_VIEWER`, `USE_CACHED_RESULT` for the AI user) | MEDIUM (probable on sf) |
| DB-10 | Can its SQL reach outside the database? (pg: `pg_write_server_files` / `pg_execute_server_program` / `pg_read_server_files`, foreign servers it may USE, EXECUTE on `dblink*` / `pg_read_file` / `lo_export`-class functions; sf: USAGE on STAGE / INTEGRATION / EXTERNAL VOLUME) | CRITICAL (write/program roles) / HIGH |

The v0.4 checks read **optional** inputs (`identity`, `policy_attachment` / `policy_references`,
`external_paths`, `audit_quality`). A missing input is a DB-06 UNKNOWN naming the exact statement
to capture; it is never a pass.

If the user has not confirmed that `--role` is the AI principal, every severity caps at
MEDIUM/possible (finding-format.md rule) and a DB-06 unknown says why.

## Read-only enforcement, per dialect

- **Postgres**: `PGOPTIONS='-c default_transaction_read_only=on'` makes the session reject
  writes at the server, defense-in-depth on top of the CI lint that proves the pack files
  contain no mutating statements.
- **Snowflake**: no session-level read-only switch exists; the CI lint on `sql/snowflake/`
  (zero mutating statements) is the guarantee, plus the pack uses only `SHOW` and
  `INFORMATION_SCHEMA` selects.

## Snowflake pack — invocation and interpretation (fixture-validated)

Run each file with the user's pre-authenticated CLI connection:

```
snow sql -c <connection-name> -f "${CLAUDE_PLUGIN_ROOT}/skills/db-access-audit/sql/snowflake/<file>.sql" > <tmp>/<file>.txt
```

Substitute `&role` / `&db` (and pii_columns.sql's `&org_restricted` / `&org_confidential`)
placeholders via `snow sql`'s `-D` defines where a file documents them.

The interpretation rules below are **computed by `eval_grants.py --dialect snowflake`** from
the captured outputs (scripts decide, the model narrates); they are documented here so a
human can verify what the script asserts:

| File | Look for | Check |
|---|---|---|
| `ai_principals.sql` | users/roles whose names suggest service or AI use; confirm with the user | — |
| `grants.sql` (`SHOW GRANTS TO ROLE <role>`) | privilege ∈ {INSERT, UPDATE, DELETE, TRUNCATE, OWNERSHIP} on any table | DB-01 |
| | privilege = SELECT with granted_on = TABLE (not VIEW) | DB-02 |
| `pii_columns.sql` | rows returned at all — every row is a PII-named column with its tier floor | DB-03 (join mentally with grants: flag columns on objects the role can SELECT) |
| `masked_views.sql` | zero masking policies AND no view whose name/definition suggests masking | DB-04 |
| `audit_logging.sql` | role lacks access to QUERY_HISTORY review, or nobody monitors it — ask the user who reviews AI query history | DB-05 (confidence probable at best; this one is partly organizational) |

| `identity.sql` (`DESCRIBE USER`, `SHOW GRANTS TO USER`) | `TYPE` ≠ SERVICE / SERVICE_AGENT; `DEFAULT_SECONDARY_ROLES` contains ALL; >1 role granted | DB-ID-01 |
| `grants.sql` | privilege = USAGE with granted_on = ROLE | DB-07 (inheritance) |
| `grants.sql` | granted_on ∈ {STAGE, INTEGRATION, EXTERNAL VOLUME} | DB-10 |
| `policy_references.sql` (`ACCOUNT_USAGE.POLICY_REFERENCES`) | readable PII column with no MASKING_POLICY reference | DB-08 |
| `masked_views.sql` statement 3 (`SHOW DYNAMIC TABLES`) | owner set and `execute_as_user` empty | DB-08 INFO |
| `audit_quality.sql` (`ACCOUNT_USAGE.GRANTS_TO_ROLES` for `GOVERNANCE_VIEWER` holders; `SHOW PARAMETERS … IN USER`) | no grantee of `SNOWFLAKE.GOVERNANCE_VIEWER`; `USE_CACHED_RESULT = true` | DB-09 (probable at best) |

**Auditor privileges (precondition, verified 2026-09-11 against Snowflake docs):** the auditing
connection needs `GRANT DATABASE ROLE SNOWFLAKE.GOVERNANCE_VIEWER TO ROLE <auditor>` for
`POLICY_REFERENCES` / `ACCESS_HISTORY` / `MASKING_POLICIES` and `SNOWFLAKE.SECURITY_VIEWER` for
`GRANTS_TO_ROLES` / `LOGIN_HISTORY` (which `audit_quality.sql` reads, because `SHOW GRANTS` has no
`OF DATABASE ROLE` form). Every recorded Snowflake input is header-validated per statement: a
renamed or missing column is a DB-06 UNKNOWN, never a pass. The INFORMATION_SCHEMA `POLICY_REFERENCES` *table function*
is deliberately not used: with only APPLY it returns just the objects the caller owns, a silent
partial result. Without the database role, DB-08 and DB-09 are UNKNOWN, not clear.

Snowflake notes that matter:
- **Agents inherit the invoking role's privileges** (Snowflake Cortex guidance) — a "read-only
  app" running as a broad role is not read-only.
- `ACCOUNT_USAGE` views lag up to 120–180 minutes and need the SNOWFLAKE database roles above
  (the older IMPORTED PRIVILEGES grant still works but is coarser); the pack prefers `SHOW` and
  `INFORMATION_SCHEMA` where they answer the question, and says "as of up to 2 hours ago" where
  only `ACCOUNT_USAGE` does (`policy_references.sql`).
- **Result cache**: reads served from the persisted result cache (24 h, extended on reuse up to
  31 days) appear with 0 rows in access history; `USE_CACHED_RESULT = FALSE` for the AI user
  closes that blind spot (DB-09).
- Output shapes vary by edition and version — Snowflake support is validated against the
  recorded fixtures in `tests/fixtures/snowflake/`, not a live CI account. The report header
  must say "Snowflake support: fixture-validated".

## Databricks Unity Catalog pack — invocation and interpretation (v0.7, fixture-validated)

Recorded mode: `eval_grants.py --dialect databricks --recorded <dir>` reads one CSV per pack file
(`grants`, `pii_columns`, `masked_views`, `policy_attachment`, `identity`, `external_paths`,
`audit_logging`). Live capture goes through the Databricks SQL CLI (`pip install
databricks-sql-cli`; `dbsqlcli --table-format csv -e "<sql>"`), authenticated by the user's own
`~/.dbsqlcli/dbsqlclirc`, PAT, or OAuth; the skill never sees the token. Two placeholders,
`${catalog}` and `${principal}`, are substituted after validation.

Identity model the module applies (`scripts/dialects/databricks.py`): the principal's **shape**
tells its kind (applicationId UUID = service principal, email = user, otherwise group; `account
users` / `users` = everyone). Grants to any group returned by `SHOW GROUPS WITH USER` apply to the
principal; catalog- and schema-level grants apply to every current and future child object and
`INHERITED_FROM` names the ancestor. Every finding's evidence says how a grant reaches the
principal: `(direct)`, `(via group X)`, `(inherited from catalog.schema)`, `(via 'account users')`.

| File | Look for | Check |
|---|---|---|
| `grants.csv` | MODIFY / ALL PRIVILEGES / INSERT / UPDATE / DELETE at any level; table ownership | DB-01 |
| | SELECT on MANAGED/EXTERNAL/STREAMING/FOREIGN tables, or SELECT at schema/catalog level | DB-02 |
| `pii_columns.csv` × readable objects | PII-named columns on readable tables (schema/catalog SELECT makes every table readable) | DB-03 |
| `masked_views.csv` + `policy_attachment.csv` | no view with a masking signal and no column mask | DB-04 |
| `audit_logging.csv` | `system.access` absent → MEDIUM; present with no grants → admins-only MEDIUM/probable | DB-05 |
| `identity.csv` | principal is a user or a group; nested group memberships; owned tables | DB-ID-01 |
| `grants.csv` | any read/write path to PII objects that is not a direct table grant (group, inherited, everyone) | DB-07 |
| `policy_attachment.csv` | readable PII column with no `column_mask` row; row filters noted; ABAC exempt principals not visible (said in evidence) | DB-08 |
| `audit_logging.csv` | `system.query` absent → MEDIUM; statement_text redacted for non-admins; 365-day retention | DB-09 |
| `external_paths.csv` | WRITE FILES / WRITE VOLUME / CREATE EXTERNAL * → CRITICAL; READ FILES / READ VOLUME / BROWSE → HIGH | DB-10 |

Always-present DB-06: the INFORMATION_SCHEMA own-grants visibility precondition. The audit cannot
tell a genuinely empty grant list from a partial one, so it says so every time.

What the pack cannot see (stated, not guessed): ABAC policy exemptions, workspace-level admin
roles, cluster-scoped credentials, and privileges in other catalogs.

## Amazon Redshift pack — invocation and interpretation (v0.8, fixture-validated)

Recorded mode: `eval_grants.py --dialect redshift --recorded <dir>` reads one CSV per pack file
(`grants`, `schema_grants`, `database_grants`, `column_grants`, `ownership`, `pii_columns`,
`masked_views`, `policy_attachment`, `identity`, `external_paths`, `iam_privileges`,
`audit_logging`). Live capture is plain `psql --csv` against port 5439 with `-v ai_user='<db user>'`
(see `sql/redshift/README.md`).

Identity model the module applies (`scripts/dialects/redshift.py`): the principal is a database
USER; privileges reach it directly, through roles (`svv_user_grants`, then `svv_role_grants` walked
transitively), through groups (`pg_group`), and through PUBLIC. A relation privilege counts only
when the identity also holds USAGE on the schema (otherwise a LOW "latent grant"). Scoped grants
(`privilege_scope = TABLES` at schema or database level) cover every current and future table.
Ownership is write authority with no grant row; column-level SELECT/UPDATE grants are read/write
paths with no relation row. Object names compare lowercased unless
`enable_case_sensitive_identifier` is true (recorded in `audit_logging.csv`); identity names compare
as recorded. `identity.csv` and `audit_logging.csv` record the AUDITOR's standing: below superuser,
grant-derived verdicts are declared partial (DB-06); below `sys:secadmin`, an empty policy result
makes DB-08 and DB-04 UNKNOWN, never "no policies".

| File | Look for | Check |
|---|---|---|
| `grants.csv` + `schema_grants.csv` + `database_grants.csv` + `column_grants.csv` + `ownership.csv` | INSERT/UPDATE/DELETE/DROP/TRUNCATE/ALTER/ALL on relations, column UPDATE, scoped writes (schema or database TABLES), relation ownership, or `usesuper` | DB-01 |
| | SELECT on TABLE / EXTERNAL TABLE with schema USAGE; column-level SELECT; scoped SELECT on TABLES (schema or database) | DB-02 (latent without USAGE → LOW) |
| `pii_columns.csv` × readable objects | PII-named columns on readable tables | DB-03 |
| `masked_views.csv` + `policy_attachment.csv` | no view with a masking signal and no masking attachment | DB-04 |
| `audit_logging.csv` | `enable_user_activity_logging` ≠ true (false by default) | DB-05 |
| `identity.csv` | superuser (CRITICAL), CREATEDB, password auth (no `IAM:`/`IAMA:` prefix), transitive roles incl. `sys:*` admin roles (CRITICAL), groups | DB-ID-01 |
| `grants.csv` + `schema_grants.csv` | paths to PII objects via role, group, PUBLIC, or scoped TABLES grants | DB-07 |
| `policy_attachment.csv` | readable PII column not among the OUTPUT columns of a masking attachment for the agent's identities or PUBLIC (an attachment to another role does nothing for it); RLS noted | DB-08 (UNKNOWN when the auditor is not secadmin and the file is empty) |
| `audit_logging.csv` | S3/CloudWatch export invisible from SQL; SYS_QUERY_HISTORY own-rows visibility; 4000-char truncation; result-cache reads | DB-09 (probable) |
| `external_paths.csv` + `iam_privileges.csv` | USAGE on external schemas (Spectrum / Glue, Hive, federated, remote Redshift, Kinesis, MSK); UNLOAD / EXTERNAL FUNCTION / CREATE MODEL grants on IAM roles → CRITICAL, COPY → HIGH | DB-10 (bucket-level IAM/S3 authorization stays a DB-06) |

## Remediation target state (the safe-db-access recipe; planner approved as a SPEC amendment 2026-09-11)

1. Dedicated AI service principal, no interactive human sharing it. On Snowflake create it with
   `TYPE = SERVICE_AGENT` (GA 2026-07-23) or `SERVICE`, and `DEFAULT_SECONDARY_ROLES = ()`, so
   secondary roles cannot widen the session.
2. `USAGE` on one curated schema only; `SELECT` on masked views only — email hashed, account
   last-4, SSN omitted. Prefer the platform's masking policy where the edition allows it
   (Snowflake DDM is Enterprise+); a policy body can call `IS_AGENT_ACTIVATED()` to withhold
   regulated data from agent sessions.
3. Where joins need a stable identifier, use a **keyed** hash (HMAC) or tokenization with the key
   held outside the AI role's reach, not a salt table in a schema the same account can read.
   Columns whose name carries a pseudonymization suffix (`*_pseudo`, `*_hash`, `*_hmac`, `*_token`)
   AND whose object is a view with a hashing/masking signal in its definition are tiered
   `Pseudonymized` by the evaluator (v0.6): DB-03 lists them as INFO and DB-08 does not count them
   as unattached PII. A base-table column named `ssn_hash` stays Restricted; without a views input
   nothing is pseudonymized. The safe-db-access planner produces exactly this shape.
   **Hashed identifiers are pseudonymized, not anonymized**: NIST SP 800-188 §4.3.2 says unkeyed
   hashing "generally does not confer security because an attacker can brute force" low-entropy
   values, and the EDPB's Guidelines 01/2025 treat pseudonymised data as personal data whose key
   must be kept separately. Say this in every remediation that mentions hashing.
4. Audit logging of the AI role's queries, reviewed by a named owner.
5. A validation script proving analytics still work AND raw base-table access is refused at the
   database layer.

## Work-context reuse

Nothing here hardcodes an org: dialect, connection, and role are arguments; the SQL packs use
placeholders. Pointing this at a corporate Snowflake later requires zero repo changes — only a
`snow` connection name and a confirmed role.
