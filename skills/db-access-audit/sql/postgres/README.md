PostgreSQL pack. Every file runs through the user's own pre-authenticated `psql`, read-only at the
session level as well as by content (CI lints these files for zero mutating statements):

    PGOPTIONS='-c default_transaction_read_only=on' psql "<conninfo>" --csv -q -v ON_ERROR_STOP=1 \
      -v ai_role='<ai-role>' \
      -v org_restricted='(^|_)(__none__)(_|$)' -v org_confidential='(^|_)(__none__)(_|$)' \
      -f <file>.sql > <tmp>/<file>.csv

Replace the two `__none__` patterns with your org profile's tokens when you have one
(`reference/org-config.md`). Files that do not use a variable simply ignore it.

Ten files: ai_principals (discovery, for when you are not sure which role the agent uses),
grants, pii_columns, masked_views, audit_logging, identity, policy_attachment, external_paths,
audit_quality, and columns (feeds the safe-db-access planner, produces no finding).

Precondition (stated at the gate): `information_schema` shows grants only where one of the
session's enabled roles is the grantor or grantee, so capture as the AI role itself, a member of
it, or a superuser. `identity.sql` records the capturing login's standing; when it could not see
the grants, the evaluator reports DB-06 "Grant visibility partial" rather than a clean result.
Always capture `identity.sql` along with `grants.sql`.

To audit without connecting from your machine, a DBA runs the commands above and hands over the
folder; then run the skill with `--recorded <folder>`.
