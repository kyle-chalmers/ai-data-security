-- 1. SERVICE IDENTITY --------------------------------------------------------------------------
-- The agent authenticates as a non-person user whose sessions carry exactly one role.
-- TYPE = SERVICE_AGENT marks the identity as an agent (agent identity, GA 2026-07): QUERY_HISTORY
-- and ACCESS_HISTORY record it and IS_AGENT_ACTIVATED() is true inside policies. TYPE = SERVICE is
-- the plain programmatic identity (key-pair / PAT) when agent identity is not in use.
-- DEFAULT_SECONDARY_ROLES = () means no other granted role is active in the session (DB-ID-01).
USE ROLE USERADMIN;
ALTER USER {{ai_user}} SET
  TYPE = {{user_type}}
  DEFAULT_ROLE = {{ai_role}}
  DEFAULT_SECONDARY_ROLES = ();
-- Extra roles granted to the user (the audit's SHOW GRANTS TO USER):
USE ROLE SECURITYADMIN;
{{revoke_user_roles}}-- Roles the AI role inherits (DB-07: USAGE on ROLE = the whole hierarchy below it):
{{revoke_role_roles}}
