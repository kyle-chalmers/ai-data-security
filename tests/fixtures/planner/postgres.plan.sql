-- ============================================================================================
-- ai-data-security safe-db-access PLAN (postgres) — generated text, NOT executed, NOT saved
-- ============================================================================================
-- Status: COMPLETE   planner tool version 1
-- AI role: ai_agent   curated schema: curated   key vault schema: vault   view owner: curated_owner
-- Audit findings this plan answers: DB-01, DB-02, DB-03, DB-04, DB-05, DB-07, DB-08, DB-09, DB-10, DB-ID-01
-- Readable base tables: 2   Restricted-tier columns: 3   Confidential-tier columns: 3
--
-- HOW TO USE: a human with DBA rights reviews every statement, runs sections 1-5 in a
-- transaction-capable session, then runs section 6 AS THE AI ROLE, then re-runs
-- /ai-data-security:db-access-audit and attaches before/after. Section 7 undoes the change.
-- The planner never connected to anything; the statements below came from fixed templates with
-- identifiers the audit captured and this tool validated (no quoting, no escaping, no values).
--
-- WHAT THIS DOES NOT DO: it does not anonymize. Hashed identifiers are PSEUDONYMIZED personal
-- data (NIST SP 800-188 §4.3.2; EDPB Guidelines 01/2025) — the keyed hash only stops the agent from
-- reading the raw value. The key lives in vault, which the AI role cannot read; rotate it on
-- the same schedule as other credentials and re-create the views afterwards. It does not defend
-- against prompt injection, and it does not change what the agent's provider retains.
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
-- The AI role becomes a login role that inherits nothing, owns nothing, and cannot reach the
-- server file system. Credentials are set out of band (\password, IAM, or a secret manager);
-- never in this file.
ALTER ROLE ai_agent NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION
  CONNECTION LIMIT 5;
-- Memberships the audit found (DB-ID-01 / DB-07): everything those roles could read, the agent could read.
REVOKE analyst_group FROM ai_agent;
-- Server roles the audit found (DB-10): these bypass every database-level permission check.
REVOKE pg_write_server_files FROM ai_agent;

-- 2. KEY VAULT FOR PSEUDONYMIZATION -----------------------------------------------------------
-- A keyed hash (HMAC-SHA-256, pgcrypto) replaces Confidential-tier identifiers so joins still
-- work. The key is generated on the server and stored where only DBAs and the view owner can
-- reach it. A salt table in the same schema as the data would NOT do this: the agent could read it.
-- pgcrypto is referenced as public.* on purpose (no search_path guessing). If your pgcrypto lives in
-- another schema, change "public." below to that schema before running; the planner does not guess.
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
CREATE SCHEMA IF NOT EXISTS vault;
REVOKE ALL ON SCHEMA vault FROM PUBLIC;
CREATE TABLE IF NOT EXISTS vault.keys (
    name        text PRIMARY KEY,
    key         bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON vault.keys FROM PUBLIC;
INSERT INTO vault.keys (name, key)
SELECT 'pii', public.gen_random_bytes(32)
WHERE NOT EXISTS (SELECT 1 FROM vault.keys WHERE name = 'pii');
-- SECURITY DEFINER: runs as the DBA who creates it, so callers never see the key.
CREATE OR REPLACE FUNCTION vault.hash_pii(value text) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, vault
AS $$
    SELECT CASE WHEN value IS NULL THEN NULL
                ELSE encode(public.hmac(convert_to(value, 'UTF8'), (SELECT k.key FROM vault.keys k WHERE k.name = 'pii'), 'sha256'::text), 'hex')
           END
$$;
REVOKE ALL ON FUNCTION vault.hash_pii(text) FROM PUBLIC;
-- Only the curated view owner may call it (section 3 creates the views under that role). CREATE
-- ROLE fails if curated_owner already exists: that is deliberate, the rollback drops this role.
CREATE ROLE curated_owner NOLOGIN NOINHERIT;
GRANT USAGE ON SCHEMA vault TO curated_owner;
GRANT EXECUTE ON FUNCTION vault.hash_pii(text) TO curated_owner;

-- 3. CURATED SCHEMA OF MASKED VIEWS ------------------------------------------------------------
-- Views run with their OWNER's privileges (security_invoker is off), so the AI role needs SELECT
-- on the view only. Restricted-tier columns are omitted entirely; Confidential-tier columns are
-- replaced by their keyed hash; everything else passes through by name.
CREATE SCHEMA IF NOT EXISTS curated AUTHORIZATION curated_owner;
GRANT USAGE ON SCHEMA app TO curated_owner;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO curated_owner;

CREATE OR REPLACE VIEW curated.customers AS
SELECT
    -- ssn: Restricted tier, omitted from the curated view
    -- card_number: Restricted tier, omitted from the curated view
    -- member_ssn: Restricted tier, omitted from the curated view
    customer_id,
    vault.hash_pii(full_name::text) AS full_name_pseudo,
    vault.hash_pii(email::text) AS email_pseudo,
    vault.hash_pii(customer_email::text) AS customer_email_pseudo,
    emailed_at,
    balance
FROM app.customers;
ALTER VIEW curated.customers OWNER TO curated_owner;

CREATE OR REPLACE VIEW curated.orders AS
SELECT
    order_id,
    customer_id,
    total
FROM app.orders;
ALTER VIEW curated.orders OWNER TO curated_owner;


-- 4. GRANTS: RAW OUT, CURATED IN ---------------------------------------------------------------
-- Direct grants (DB-01 / DB-02 / DB-03):
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA app FROM ai_agent;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA app FROM ai_agent;
REVOKE ALL PRIVILEGES ON SCHEMA app FROM ai_agent;
-- Default privileges that would re-grant future objects automatically (DB-07). ALTER DEFAULT
-- PRIVILEGES edits one grantor's defaults, hence FOR ROLE <the role the audit saw as grantor>:
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA app REVOKE ALL ON TABLES FROM ai_agent;
-- PUBLIC grants (DB-07). These affect EVERY role in the database, not just the AI role, so they are
-- rendered commented out unless the planner was run with --include-public-revokes after review:
-- REVIEW, then remove this comment marker to run: REVOKE SELECT ON app.orders FROM PUBLIC;
-- The only read surface the AI role keeps:
GRANT USAGE ON SCHEMA curated TO ai_agent;
GRANT SELECT ON ALL TABLES IN SCHEMA curated TO ai_agent;

-- 5. AUDIT TRAIL --------------------------------------------------------------------------------
-- Per-role statement logging needs no restart and records every statement the AI role runs in the
-- server log (DB-05 / DB-09). The log's RETENTION is decided outside the database (log rotation,
-- log shipping); this plan cannot set it, so check it. Object-level audit of SELECTs needs pgaudit
-- in shared_preload_libraries (a restart), which is out of this plan's scope:
--   shared_preload_libraries = 'pgaudit'   then   ALTER ROLE ai_agent SET pgaudit.log = 'read, write';
ALTER ROLE ai_agent SET log_statement = 'all';
ALTER ROLE ai_agent SET log_min_duration_statement = 0;

-- 6. VALIDATION — run this AS ai_agent (psql -U ai_agent ... -f this_section) ----------------
-- Every row must show ok = t. The first rows prove the analytics surface works; the rest prove
-- the raw surface, the vault, inherited roles, and server roles are gone.
SELECT check_name, expected, actual, (expected = actual) AS ok FROM (
    SELECT 'session role is the AI role' AS check_name, 'ai_agent' AS expected, current_user::text AS actual
    UNION ALL SELECT 'role does not inherit', 'false', (SELECT rolinherit::text FROM pg_roles WHERE rolname = current_user)
    UNION ALL SELECT 'role is not superuser', 'false', (SELECT rolsuper::text FROM pg_roles WHERE rolname = current_user)
    UNION ALL SELECT 'role cannot bypass RLS', 'false', (SELECT rolbypassrls::text FROM pg_roles WHERE rolname = current_user)
    UNION ALL SELECT 'curated schema usable', 'true', has_schema_privilege('curated', 'USAGE')::text
    UNION ALL SELECT 'vault schema NOT usable', 'false', has_schema_privilege('vault', 'USAGE')::text
    UNION ALL SELECT 'vault.hash_pii NOT executable', 'false', (SELECT has_function_privilege(p.oid, 'EXECUTE') FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'vault' AND p.proname = 'hash_pii')::text
    UNION ALL SELECT 'curated view curated.customers readable', 'true', has_table_privilege('curated.customers', 'SELECT')::text
    UNION ALL SELECT 'curated view curated.customers NOT writable', 'false', has_table_privilege('curated.customers', 'INSERT')::text
    UNION ALL SELECT 'analytics query on curated.customers runs', 'true', (SELECT count(*) >= 0 FROM curated.customers)::text
    UNION ALL SELECT 'curated view curated.orders readable', 'true', has_table_privilege('curated.orders', 'SELECT')::text
    UNION ALL SELECT 'curated view curated.orders NOT writable', 'false', has_table_privilege('curated.orders', 'INSERT')::text
    UNION ALL SELECT 'analytics query on curated.orders runs', 'true', (SELECT count(*) >= 0 FROM curated.orders)::text
    UNION ALL SELECT 'raw app.customers NOT readable', 'false', (SELECT has_table_privilege(c.oid, 'SELECT') FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'customers')::text
    UNION ALL SELECT 'raw app.customers NOT writable', 'false', (SELECT has_table_privilege(c.oid, 'INSERT') OR has_table_privilege(c.oid, 'UPDATE') OR has_table_privilege(c.oid, 'DELETE') FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'customers')::text
    UNION ALL SELECT 'raw app.orders NOT readable', 'false', (SELECT has_table_privilege(c.oid, 'SELECT') FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'orders')::text
    UNION ALL SELECT 'raw app.orders NOT writable', 'false', (SELECT has_table_privilege(c.oid, 'INSERT') OR has_table_privilege(c.oid, 'UPDATE') OR has_table_privilege(c.oid, 'DELETE') FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'orders')::text
    UNION ALL SELECT 'NOT a member of analyst_group', 'false', pg_has_role(current_user, 'analyst_group', 'MEMBER')::text
    UNION ALL SELECT 'NOT a member of pg_write_server_files', 'false', pg_has_role(current_user, 'pg_write_server_files', 'MEMBER')::text
) AS checks
ORDER BY check_name;

-- 7. ROLLBACK — restores the INSECURE state the audit found. Keep for emergencies only. -----------
-- Scope: exactly the objects and grants sections 1-5 created. curated_owner must be the role this
-- plan created (section 2 refuses to run if it already existed), so dropping it removes nothing else.
DROP SCHEMA IF EXISTS curated CASCADE;
DROP SCHEMA IF EXISTS vault CASCADE;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA app FROM curated_owner;
REVOKE ALL PRIVILEGES ON SCHEMA app FROM curated_owner;
DROP ROLE IF EXISTS curated_owner;
ALTER ROLE ai_agent INHERIT CONNECTION LIMIT -1;
ALTER ROLE ai_agent RESET log_statement;
ALTER ROLE ai_agent RESET log_min_duration_statement;
GRANT analyst_group TO ai_agent;
GRANT pg_write_server_files TO ai_agent;
GRANT USAGE ON SCHEMA app TO ai_agent;
GRANT SELECT ON app.customers TO ai_agent;
GRANT SELECT ON app.orders TO ai_agent;
GRANT INSERT ON app.customers TO ai_agent;
GRANT UPDATE ON app.customers TO ai_agent;
GRANT INSERT ON app.orders TO ai_agent;
GRANT UPDATE ON app.orders TO ai_agent;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA app GRANT SELECT ON TABLES TO ai_agent;
-- REVIEW, then remove this comment marker to run: GRANT SELECT ON app.orders TO PUBLIC;

