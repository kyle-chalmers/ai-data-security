-- policy_references.sql — which masking / row-access policies are ATTACHED to columns in the
-- target database. Uses ACCOUNT_USAGE (latency up to 120 minutes) because the
-- INFORMATION_SCHEMA table function returns only objects the caller owns unless it holds
-- global APPLY MASKING POLICY. Requires the SNOWFLAKE.GOVERNANCE_VIEWER database role:
--   GRANT DATABASE ROLE SNOWFLAKE.GOVERNANCE_VIEWER TO ROLE <auditor_role>;
-- If this statement fails for lack of privilege, DB-08 is reported UNKNOWN with that GRANT.
-- Read-only. Run with: snow sql -c <connection> -D "db=YOUR_DATABASE" -f policy_references.sql
SELECT policy_db, policy_schema, policy_name, policy_kind,
       ref_database_name, ref_schema_name, ref_entity_name, ref_column_name, policy_status
FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
WHERE ref_database_name = '&{ db }'
ORDER BY ref_schema_name, ref_entity_name, ref_column_name;
