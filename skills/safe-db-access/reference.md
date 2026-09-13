# safe-db-access — design notes

## What the plan is built from

`eval_grants.py` (tool version 4) emits a `plan_inputs` block next to its findings: the readable
base tables, PII columns with tiers, write grants, inherited roles, server/file roles, PUBLIC
grants, default-privilege schemas, stages/integrations, and (Snowflake) the user's TYPE and
secondary-role setting. It is value-free (names only) and independent of the findings, so a
missing input is `null` there, never inferred. Postgres additionally needs `columns.sql` (added
to the pack in v0.6) because Postgres has no `SELECT * EXCLUDE`; without it a PII-bearing table's
view is rendered as an INCOMPLETE placeholder and the header says so.

## Why templates and not generation

Design rule 1 (scripts decide, the model narrates) applies to remediation text as much as to
verdicts. Every statement in a plan exists in `templates/<dialect>/` before the run; the script
only picks fragments and substitutes identifiers that passed `IDENT`. An unfilled `{{slot}}`
aborts the whole render (exit 3). This is why a hostile object name in the warehouse cannot
become SQL: it is listed under NOT RENDERED and excluded.

## Recipe, and the research it answers

| Section | Postgres | Snowflake | Corrects |
|---|---|---|---|
| 1 identity | `ALTER ROLE … NOINHERIT NOSUPERUSER … NOBYPASSRLS`, revoke memberships and server roles | `ALTER USER … TYPE = SERVICE_AGENT DEFAULT_SECONDARY_ROLES = ()`, revoke extra roles | C4, C10, thesis principle 3 (agent identity is now a checkable fact) |
| 2 vault | pgcrypto HMAC-SHA-256 in a SECURITY DEFINER function; key in `vault.keys` with no PUBLIC access | SHA-256 over a server-generated key in `VAULT.KEYS`, owner's-rights UDF | C5: hashing is pseudonymization; the key must not sit next to the data |
| 3 curated | views owned by `curated_owner` (a role the plan creates; CREATE ROLE fails if it exists, on purpose); Restricted omitted, Confidential hashed, rest by name; a table whose basename repeats across schemas gets `<schema>_<table>`; a table with no projectable column is INCOMPLETE | secure views with `EXCLUDE`; 3b STRING masking policy with `IS_AGENT_ACTIVATED() OR CURRENT_ROLE()` attached only to STRING-typed Restricted raw columns (others → INCOMPLETE), Enterprise+ | C6: masking attached, not just present |
| 4 grants | revoke all on raw schemas; default privileges `FOR ROLE <captured grantor>` (per-schema and global); PUBLIC revocations rendered commented out unless `--include-public-revokes` (they affect every role) with the exact captured privilege; grant curated | revoke raw/future/views/usage and stages; grant curated views incl. FUTURE | DB-01/02/03/07/10 |
| 5 audit | per-role `log_statement = 'all'`; pgaudit needs a restart (stated, not planned) | `USE_CACHED_RESULT = FALSE`; auditor role gets GOVERNANCE_VIEWER + SECURITY_VIEWER | C7: cache reads, admin-only views, retention lives elsewhere |
| 6 validate | one query, run as the AI role, every row `ok = t` (OID-based privilege checks so no schema USAGE is needed) | statements that each return expected/actual (INFORMATION_SCHEMA.TABLE_PRIVILEGES, CURRENT_SECONDARY_ROLES, curated counts); optional erroring probes commented out | "trust, then verify" |
| 7 rollback | drops curated + vault (CASCADE), revokes exactly the owner's raw reads, drops the plan-created owner role, re-grants everything the audit found (memberships, selects, writes, default privileges FOR ROLE, PUBLIC if included) | same, plus UNSET MASKING POLICY, stage privileges | reversibility |

## Refusals and what they protect

| Input | Rule | Why |
|---|---|---|
| any CLI identifier | `^[A-Za-z_][A-Za-z0-9_]{0,127}$`, exit 2, empty stdout | the planner never quotes or escapes |
| `--curated-schema`, `--vault-schema` | must not equal any raw schema the audit saw, nor `public` / `pg_catalog` / `information_schema` / `snowflake` | rollback DROPs these schemas CASCADE |
| `--owner-role` | must differ from the AI role | the owner reads raw tables |
| `--auditor-role` (Snowflake) | must differ from the AI role and the owner | governance views would land on the agent |
| object names from the warehouse | invalid → NOT RENDERED, listed by hash handle only | a name with a newline or `--` could break out of a SQL comment |
| `findings[].check_id` from the audit JSON | must match `^[A-Z]{2,4}(-[A-Z0-9]+)+$` or it is dropped from the header | same comment-escape risk |
| default privileges without a captured grantor | statement not rendered, plan INCOMPLETE | `ALTER DEFAULT PRIVILEGES` without `FOR ROLE` edits the DBA's own defaults, not the creator's |

## Pseudonymized: provenance, not names

The evaluator tiers a column `Pseudonymized` only when its name carries a pseudonymization suffix
**and** the object is a view whose definition shows a hashing/masking signal (Postgres
`masked_views.has_masking_signal`; Snowflake `SHOW VIEWS` `text`). A base-table column named
`ssn_hash` stays Restricted. Without a views input, nothing is pseudonymized (fail closed). This is
what lets the plan's own output stop re-triggering the findings it fixed without opening a
name-only bypass.

## CI proof

`tests/postgres-fixture-check.sh` renders the plan from the fixture audit, applies sections 1–5 as
the DBA, runs section 6 as `ai_agent` and requires every row `ok = t`, attempts a raw read as
`ai_agent` and requires it to fail, re-runs the audit pack and requires DB-01/02/03/07/10/ID-01 to
be gone, then applies section 7 and requires them back. `tests/run-fixture-checks.sh` diffs both
dialects' renders against goldens under `tests/fixtures/planner/` and checks the refusal paths.
`dev/validate.sh` lints `plan.py` for anything that could connect or write.
