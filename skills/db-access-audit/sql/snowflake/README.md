Snowflake pack. Every file runs through the user's own pre-authenticated Snowflake CLI connection,
and the evaluator reads the `snow sql` table output as-is (save it as `.txt`):

    snow sql -c <connection> -f ai_principals.sql   > <tmp>/ai_principals.txt
    snow sql -c <connection> -f audit_logging.sql   > <tmp>/audit_logging.txt
    snow sql -c <connection> -D "role=<AI_ROLE>" -f grants.sql > <tmp>/grants.txt
    snow sql -c <connection> -D "user=<AI_USER>" -f identity.sql > <tmp>/identity.txt
    snow sql -c <connection> -D "user=<AI_USER>" -f audit_quality.sql > <tmp>/audit_quality.txt
    snow sql -c <connection> -D "db=<DATABASE>" -f masked_views.sql > <tmp>/masked_views.txt
    snow sql -c <connection> -D "db=<DATABASE>" -f policy_references.sql > <tmp>/policy_references.txt
    snow sql -c <connection> -D "db=<DATABASE>" \
      -D "org_restricted=(^|_)(__none__)(_|$)" -D "org_confidential=(^|_)(__none__)(_|$)" \
      -f pii_columns.sql > <tmp>/pii_columns.txt

Replace the two `__none__` patterns with your org profile's tokens when you have one
(`reference/org-config.md`). `pii_columns.sql` is per database; run it once for each database of
interest.

Preconditions (stated at the gate): the auditing role needs the `SNOWFLAKE.GOVERNANCE_VIEWER`
database role for `policy_references.sql` (DB-08) and `SNOWFLAKE.SECURITY_VIEWER` for
`audit_quality.sql` (DB-09). Both read `SNOWFLAKE.ACCOUNT_USAGE`, which can lag up to 120 minutes.
Without them those checks are reported UNKNOWN, never clear. Do not run the audit as ACCOUNTADMIN.

Snowflake support is validated against the recorded fixtures in `tests/fixtures/snowflake/`, not a
live CI account, and every report says so. Interpretation rules per file are in `../../reference.md`.
