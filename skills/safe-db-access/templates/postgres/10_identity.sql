-- 1. SERVICE IDENTITY --------------------------------------------------------------------------
-- The AI role becomes a login role that inherits nothing, owns nothing, and cannot reach the
-- server file system. Credentials are set out of band (\password, IAM, or a secret manager);
-- never in this file.
ALTER ROLE {{ai_role}} NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION
  CONNECTION LIMIT {{connection_limit}};
-- Memberships the audit found (DB-ID-01 / DB-07): everything those roles could read, the agent could read.
{{revoke_memberships}}-- Server roles the audit found (DB-10): these bypass every database-level permission check.
{{revoke_server_roles}}
