-- ============================================================================================
-- ai-data-security safe-db-access PLAN (snowflake) — generated text, NOT executed, NOT saved
-- ============================================================================================
-- Status: COMPLETE   planner tool version 1
-- AI user: AI_AGENT   AI role: AI_AGENT   database: ANALYTICS   curated schema: CURATED   key vault schema: VAULT   view owner: SYSADMIN
-- Audit findings this plan answers: DB-01, DB-02, DB-03, DB-04, DB-05, DB-07, DB-08, DB-09, DB-10, DB-ID-01
-- Readable base tables: 2   Restricted-tier columns: 2   Confidential-tier columns: 2
--
-- HOW TO USE: a human with SECURITYADMIN/SYSADMIN rights reviews every statement, runs sections
-- 1-5 (each USE ROLE is stated), then runs section 6 AS THE AI ROLE, then re-runs
-- /ai-data-security:db-access-audit (--recorded works) and attaches before/after. Section 7 undoes
-- the change. Snowflake support in this plugin is fixture-validated, not live-tested: run section 6.
-- The planner never connected to anything; the statements below came from fixed templates with
-- identifiers the audit captured and this tool validated (no quoting, no escaping, no values).
--
-- WHAT THIS DOES NOT DO: it does not anonymize. Hashed identifiers are PSEUDONYMIZED personal
-- data (NIST SP 800-188 §4.3.2; EDPB Guidelines 01/2025) — the keyed hash only stops the agent from
-- reading the raw value. The key lives in ANALYTICS.VAULT, which the AI role cannot read;
-- External Tokenization (Enterprise) is the stronger alternative because the key leaves Snowflake
-- entirely. It does not defend against prompt injection, and it does not change provider retention.
--
-- INCOMPLETE items (fix and re-plan before executing):
--   (none)
-- NOT RENDERED (identifiers the planner refused; review these objects by hand):
--   (none)
-- Sources:
--   - NIST SP 800-188 De-Identifying Government Datasets §4.3.2 (hashing direct identifiers is not recommended)
--   - Snowflake docs: Agent identity (SERVICE_AGENT users, agent-marked sessions; GA 2026-07-23)
--   - Snowflake docs: Overview of Access Control (primary/secondary roles aggregate privileges)
--   - PostgreSQL docs: Predefined Roles (pg_write_server_files / pg_execute_server_program bypass database permission checks)
--   - OWASP ASI03:2026 Identity & Privilege Abuse (Top 10 for Agentic Applications)
--   - NIST SP 800-122 (PII confidentiality impact levels)
-- ============================================================================================

-- 1. SERVICE IDENTITY --------------------------------------------------------------------------
-- The agent authenticates as a non-person user whose sessions carry exactly one role.
-- TYPE = SERVICE_AGENT marks the identity as an agent (agent identity, GA 2026-07): QUERY_HISTORY
-- and ACCESS_HISTORY record it and IS_AGENT_ACTIVATED() is true inside policies. TYPE = SERVICE is
-- the plain programmatic identity (key-pair / PAT) when agent identity is not in use.
-- DEFAULT_SECONDARY_ROLES = () means no other granted role is active in the session (DB-ID-01).
USE ROLE USERADMIN;
ALTER USER AI_AGENT SET
  TYPE = SERVICE_AGENT
  DEFAULT_ROLE = AI_AGENT
  DEFAULT_SECONDARY_ROLES = ();
-- Extra roles granted to the user (the audit's SHOW GRANTS TO USER):
USE ROLE SECURITYADMIN;
REVOKE ROLE ANALYST FROM USER AI_AGENT;
-- Roles the AI role inherits (DB-07: USAGE on ROLE = the whole hierarchy below it):
REVOKE ROLE ANALYST FROM ROLE AI_AGENT;

-- 2. KEY VAULT FOR PSEUDONYMIZATION -----------------------------------------------------------
-- A keyed SHA-256 replaces Confidential-tier identifiers so joins still work. The key is generated
-- inside Snowflake and stored in a schema the AI role has no USAGE on. The UDF runs with its
-- OWNER's rights, so callers never read the key. A salt table next to the data would not do this.
USE ROLE SYSADMIN;
CREATE SCHEMA IF NOT EXISTS ANALYTICS.VAULT;
CREATE TABLE IF NOT EXISTS ANALYTICS.VAULT.KEYS (
    NAME        STRING PRIMARY KEY,
    KEY         STRING NOT NULL,
    CREATED_AT  TIMESTAMP_TZ NOT NULL DEFAULT CURRENT_TIMESTAMP()
);
INSERT INTO ANALYTICS.VAULT.KEYS (NAME, KEY)
SELECT 'pii', RANDSTR(64, RANDOM())
WHERE NOT EXISTS (SELECT 1 FROM ANALYTICS.VAULT.KEYS WHERE NAME = 'pii');
CREATE OR REPLACE FUNCTION ANALYTICS.VAULT.HASH_PII(V STRING)
RETURNS STRING
AS
$$
    SELECT IFF(V IS NULL, NULL, SHA2(CONCAT((SELECT KEY FROM ANALYTICS.VAULT.KEYS WHERE NAME = 'pii'), V), 256))
$$;

-- 3. CURATED SCHEMA OF SECURE VIEWS -------------------------------------------------------------
-- Secure views hide their definition and evaluate with the OWNER's privileges. Restricted-tier
-- columns are EXCLUDEd; Confidential-tier columns are replaced by their keyed hash.
USE ROLE SYSADMIN;
CREATE SCHEMA IF NOT EXISTS ANALYTICS.CURATED;
CREATE OR REPLACE SECURE VIEW ANALYTICS.CURATED.CUSTOMERS AS
SELECT
    -- CARD_NUMBER: Restricted tier, omitted
    -- SSN: Restricted tier, omitted
    * EXCLUDE (CARD_NUMBER, EMAIL, FULL_NAME, SSN),
    ANALYTICS.VAULT.HASH_PII(EMAIL::STRING) AS EMAIL_PSEUDO,
    ANALYTICS.VAULT.HASH_PII(FULL_NAME::STRING) AS FULL_NAME_PSEUDO
FROM ANALYTICS.APP.CUSTOMERS;

CREATE OR REPLACE SECURE VIEW ANALYTICS.CURATED.ORDERS AS
SELECT
    *
FROM ANALYTICS.APP.ORDERS;


-- 3b. MASKING POLICY ON THE RAW TABLES (defense in depth; Enterprise or higher) -----------------
-- Edition: Enterprise or higher confirmed by the operator; masking policies are available.
-- Even if a future grant reaches the raw table, an agent-marked session or the AI role sees NULL.
-- IS_AGENT_ACTIVATED() is true in sessions of a SERVICE_AGENT identity; CURRENT_ROLE() covers a
-- plain SERVICE user. Everyone else keeps seeing the value, so nothing breaks for people.
USE ROLE SYSADMIN;
CREATE MASKING POLICY IF NOT EXISTS ANALYTICS.CURATED.MASK_FOR_AGENTS AS (VAL STRING) RETURNS STRING ->
  CASE WHEN IS_AGENT_ACTIVATED() OR CURRENT_ROLE() = 'AI_AGENT' THEN NULL ELSE VAL END;
ALTER TABLE ANALYTICS.APP.CUSTOMERS MODIFY COLUMN CARD_NUMBER SET MASKING POLICY ANALYTICS.CURATED.MASK_FOR_AGENTS;
ALTER TABLE ANALYTICS.APP.CUSTOMERS MODIFY COLUMN SSN SET MASKING POLICY ANALYTICS.CURATED.MASK_FOR_AGENTS;

-- 4. GRANTS: RAW OUT, CURATED IN ---------------------------------------------------------------
USE ROLE SECURITYADMIN;
-- Direct grants on raw schemas (DB-01 / DB-02 / DB-03):
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA ANALYTICS.APP FROM ROLE AI_AGENT;
REVOKE ALL PRIVILEGES ON FUTURE TABLES IN SCHEMA ANALYTICS.APP FROM ROLE AI_AGENT;
REVOKE ALL PRIVILEGES ON ALL VIEWS IN SCHEMA ANALYTICS.APP FROM ROLE AI_AGENT;
REVOKE USAGE ON SCHEMA ANALYTICS.APP FROM ROLE AI_AGENT;
-- Paths outside the database (DB-10):
REVOKE ALL PRIVILEGES ON STAGE ANALYTICS.APP.EXPORTS FROM ROLE AI_AGENT;
-- The only read surface the AI role keeps:
GRANT USAGE ON DATABASE ANALYTICS TO ROLE AI_AGENT;
GRANT USAGE ON SCHEMA ANALYTICS.CURATED TO ROLE AI_AGENT;
GRANT SELECT ON ALL VIEWS IN SCHEMA ANALYTICS.CURATED TO ROLE AI_AGENT;
GRANT SELECT ON FUTURE VIEWS IN SCHEMA ANALYTICS.CURATED TO ROLE AI_AGENT;

-- 5. AUDIT TRAIL --------------------------------------------------------------------------------
-- Result-cache reuse would let the agent read a cached result without a new ACCESS_HISTORY row
-- (DB-09); turn it off for the AI user. Give a non-admin auditor role the two SNOWFLAKE database
-- roles the audit itself needs, so someone other than ACCOUNTADMIN can read QUERY_HISTORY,
-- ACCESS_HISTORY (Enterprise or higher), and GRANTS_TO_ROLES (DB-05 / DB-09). RETENTION caveat:
-- ACCOUNT_USAGE keeps 365 days and lags up to 120 minutes; export to your SIEM for longer.
USE ROLE USERADMIN;
ALTER USER AI_AGENT SET USE_CACHED_RESULT = FALSE;
USE ROLE SECURITYADMIN;
CREATE ROLE IF NOT EXISTS GOVERNANCE_AUDITOR;
GRANT DATABASE ROLE SNOWFLAKE.GOVERNANCE_VIEWER TO ROLE GOVERNANCE_AUDITOR;
GRANT DATABASE ROLE SNOWFLAKE.SECURITY_VIEWER TO ROLE GOVERNANCE_AUDITOR;

-- 6. VALIDATION — run this AS the AI identity (USE ROLE AI_AGENT, or connect as AI_AGENT) ---------
-- Every statement here is meant to SUCCEED and return one row whose `actual` equals `expected`; a
-- statement that errors is itself a failed check. The commented probes at the end are optional
-- manual checks that are EXPECTED to error. Snowflake support in this plugin is fixture-validated,
-- not live-tested: this section is how you prove the plan on your account.
USE ROLE AI_AGENT;
SELECT 'session identity' AS check_name, 'AI_AGENT/AI_AGENT' AS expected,
       CURRENT_USER() || '/' || CURRENT_ROLE() AS actual;                                  -- EXPECT: actual = expected
SELECT 'no secondary roles active' AS check_name, '[]' AS expected,
       PARSE_JSON(CURRENT_SECONDARY_ROLES()):roles::STRING AS actual;                       -- EXPECT: actual = []
SELECT 'no privileges in VAULT' AS check_name, 0 AS expected, COUNT(*) AS actual
FROM ANALYTICS.INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE GRANTEE = 'AI_AGENT' AND TABLE_SCHEMA = 'VAULT';  -- EXPECT: actual = 0
SELECT 'no table privileges in APP' AS check_name, 0 AS expected, COUNT(*) AS actual
FROM ANALYTICS.INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE GRANTEE = 'AI_AGENT' AND TABLE_SCHEMA = 'APP';   -- EXPECT: actual = 0
SELECT 'CURATED.CUSTOMERS readable' AS check_name, TRUE AS expected, COUNT(*) >= 0 AS actual FROM ANALYTICS.CURATED.CUSTOMERS;   -- EXPECT: actual = TRUE
SELECT 'CURATED.ORDERS readable' AS check_name, TRUE AS expected, COUNT(*) >= 0 AS actual FROM ANALYTICS.CURATED.ORDERS;   -- EXPECT: actual = TRUE
-- SELECT COUNT(*) FROM ANALYTICS.APP.CUSTOMERS;   -- optional manual probe: EXPECT ERROR (raw table not authorized)
-- SELECT COUNT(*) FROM ANALYTICS.APP.ORDERS;   -- optional manual probe: EXPECT ERROR (raw table not authorized)
SHOW GRANTS TO ROLE AI_AGENT;                                -- EXPECT: USAGE on ANALYTICS and ANALYTICS.CURATED, SELECT on views only

-- 7. ROLLBACK — restores the INSECURE state the audit found. Keep for emergencies only. -----------
USE ROLE SECURITYADMIN;
REVOKE SELECT ON FUTURE VIEWS IN SCHEMA ANALYTICS.CURATED FROM ROLE AI_AGENT;
REVOKE ALL PRIVILEGES ON ALL VIEWS IN SCHEMA ANALYTICS.CURATED FROM ROLE AI_AGENT;
REVOKE USAGE ON SCHEMA ANALYTICS.CURATED FROM ROLE AI_AGENT;
GRANT USAGE ON SCHEMA ANALYTICS.APP TO ROLE AI_AGENT;
GRANT SELECT ON TABLE ANALYTICS.APP.CUSTOMERS TO ROLE AI_AGENT;
GRANT SELECT ON TABLE ANALYTICS.APP.ORDERS TO ROLE AI_AGENT;
GRANT INSERT ON TABLE ANALYTICS.APP.CUSTOMERS TO ROLE AI_AGENT;
GRANT UPDATE ON TABLE ANALYTICS.APP.CUSTOMERS TO ROLE AI_AGENT;
GRANT USAGE ON STAGE ANALYTICS.APP.EXPORTS TO ROLE AI_AGENT;
GRANT ROLE ANALYST TO ROLE AI_AGENT;
GRANT ROLE ANALYST TO USER AI_AGENT;
USE ROLE SYSADMIN;
ALTER TABLE ANALYTICS.APP.CUSTOMERS MODIFY COLUMN CARD_NUMBER UNSET MASKING POLICY;
ALTER TABLE ANALYTICS.APP.CUSTOMERS MODIFY COLUMN SSN UNSET MASKING POLICY;
DROP SCHEMA IF EXISTS ANALYTICS.CURATED;
DROP SCHEMA IF EXISTS ANALYTICS.VAULT;
USE ROLE USERADMIN;
ALTER USER AI_AGENT UNSET DEFAULT_SECONDARY_ROLES, USE_CACHED_RESULT;

