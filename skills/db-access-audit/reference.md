# db-access-audit reference

## Check map (both dialects)

| Check | Question | Severity (confirmed principal) |
|---|---|---|
| DB-01 | Does the AI principal hold write privileges? | CRITICAL |
| DB-02 | Does it read base tables instead of governed views? | HIGH |
| DB-03 | Are PII-named columns readable unmasked? | HIGH (Restricted floor) / MEDIUM (Confidential floor) |
| DB-04 | Is there any masked/governed view layer at all? | MEDIUM |
| DB-05 | Is there any audit trail of its queries? | MEDIUM |
| DB-06 | Anything the audit could not verify | UNKNOWN (fail-closed) |

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

Snowflake notes that matter:
- **Agents inherit the invoking role's privileges** (Snowflake Cortex guidance) — a "read-only
  app" running as a broad role is not read-only.
- `ACCOUNT_USAGE` views lag up to ~2–3h and require the IMPORTED PRIVILEGES grant; the pack
  prefers `SHOW` and `INFORMATION_SCHEMA` to avoid both problems. Where only `ACCOUNT_USAGE`
  answers, report UNKNOWN rather than stale certainty.
- Output shapes vary by edition and version — Snowflake support is validated against the
  recorded fixtures in `tests/fixtures/snowflake/`, not a live CI account. The report header
  must say "Snowflake support: fixture-validated".

## Remediation target state (the v2 safe-db-access recipe)

1. Dedicated AI service principal, no interactive human sharing it.
2. `USAGE` on one curated schema only; `SELECT` on masked views only — email hashed, account
   last-4, SSN omitted.
3. Per-row salted hashing where joins are needed; the salt table lives in a schema the AI role
   cannot read.
4. Audit logging of the AI role's queries, reviewed by a named owner.
5. A validation script proving analytics still work AND raw base-table access is refused at the
   database layer.

## Work-context reuse

Nothing here hardcodes an org: dialect, connection, and role are arguments; the SQL packs use
placeholders. Pointing this at a corporate Snowflake later requires zero repo changes — only a
`snow` connection name and a confirmed role.
