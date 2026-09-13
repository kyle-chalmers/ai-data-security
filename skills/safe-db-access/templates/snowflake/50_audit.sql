-- 5. AUDIT TRAIL --------------------------------------------------------------------------------
-- Result-cache reuse would let the agent read a cached result without a new ACCESS_HISTORY row
-- (DB-09); turn it off for the AI user. Give a non-admin auditor role the two SNOWFLAKE database
-- roles the audit itself needs, so someone other than ACCOUNTADMIN can read QUERY_HISTORY,
-- ACCESS_HISTORY (Enterprise or higher), and GRANTS_TO_ROLES (DB-05 / DB-09). RETENTION caveat:
-- ACCOUNT_USAGE keeps 365 days and lags up to 120 minutes; export to your SIEM for longer.
USE ROLE USERADMIN;
ALTER USER {{ai_user}} SET USE_CACHED_RESULT = FALSE;
USE ROLE SECURITYADMIN;
CREATE ROLE IF NOT EXISTS {{auditor_role}};
GRANT DATABASE ROLE SNOWFLAKE.GOVERNANCE_VIEWER TO ROLE {{auditor_role}};
GRANT DATABASE ROLE SNOWFLAKE.SECURITY_VIEWER TO ROLE {{auditor_role}};

