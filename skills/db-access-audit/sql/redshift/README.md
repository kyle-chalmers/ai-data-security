Amazon Redshift pack (v0.8). Redshift speaks the PostgreSQL protocol, so every file runs through the
user's own pre-authenticated `psql` (port 5439) with client-side variable substitution and CSV output:

    psql "<conninfo>" --csv -q -v ON_ERROR_STOP=1 -v ai_user='<ai-user>' \
      -v org_restricted='(^|_)(__none__)(_|$)' -v org_confidential='(^|_)(__none__)(_|$)' \
      -f <file>.sql > <tmp>/<file>.csv

`ai_user` is the database USER the agent connects as (IAM-auth users appear as `IAM:<name>` or
`IAMA:<name>`); roles and groups are expanded by the evaluator from identity.csv.

Twelve files: grants, schema_grants, database_grants, column_grants, ownership, pii_columns, masked_views,
policy_attachment, identity, external_paths, iam_privileges, audit_logging (plus ai_principals for discovery).

Preconditions (stated at the gate; audit_logging.csv records whether the auditor was a superuser and the
evaluator fails closed otherwise): SVV_RELATION_PRIVILEGES / SVV_COLUMN_PRIVILEGES show other identities'
rows only to superusers (or SYSLOG ACCESS UNRESTRICTED); SVV_*_GRANTS / SVV_SCHEMA|DATABASE|IAM_PRIVILEGES
need ACCESS SYSTEM TABLE; SVV_ATTACHED_MASKING_POLICY / SVV_RLS_ATTACHED_POLICY return ZERO ROWS to anyone
but superusers and sys:secadmin. Capture as a superuser. There is no session-level read-only switch; the
CI lint on sql/redshift/ is the guarantee.
