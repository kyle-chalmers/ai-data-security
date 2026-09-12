-- audit_quality.sql — who can actually review agent activity, and whether result-cache reuse
-- can hide reads from ACCESS_HISTORY. ACCESS_HISTORY itself requires Enterprise Edition and the
-- SNOWFLAKE.GOVERNANCE_VIEWER database role; QUERY_HISTORY.agent_type / ACCESS_HISTORY.agents_info
-- mark agent sessions when the user is a SERVICE_AGENT (agent identity, GA 2026-07-23).
-- Statement 1 reads ACCOUNT_USAGE.GRANTS_TO_ROLES (needs SNOWFLAKE.SECURITY_VIEWER; latency up to
-- 120 minutes) because SHOW GRANTS has no "OF DATABASE ROLE" form.
-- Read-only. Run with: snow sql -c <connection> -D "user=YOUR_AI_USER" -f audit_quality.sql
SELECT grantee_name, granted_to, name, granted_on, privilege
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
WHERE granted_on = 'DATABASE_ROLE'
  AND name = 'GOVERNANCE_VIEWER'
  AND table_catalog = 'SNOWFLAKE'
  AND deleted_on IS NULL
ORDER BY grantee_name;
SHOW PARAMETERS LIKE 'USE_CACHED_RESULT' IN USER &{ user };
