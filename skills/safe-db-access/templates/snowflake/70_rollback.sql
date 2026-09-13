-- 7. ROLLBACK — restores the INSECURE state the audit found. Keep for emergencies only. -----------
USE ROLE SECURITYADMIN;
REVOKE SELECT ON FUTURE VIEWS IN SCHEMA {{db}}.{{curated}} FROM ROLE {{ai_role}};
REVOKE ALL PRIVILEGES ON ALL VIEWS IN SCHEMA {{db}}.{{curated}} FROM ROLE {{ai_role}};
REVOKE USAGE ON SCHEMA {{db}}.{{curated}} FROM ROLE {{ai_role}};
{{regrant_selects}}{{regrant_writes}}{{regrant_external}}{{regrant_role_roles}}{{regrant_user_roles}}USE ROLE {{owner_role}};
{{detach_policies}}DROP SCHEMA IF EXISTS {{db}}.{{curated}};
DROP SCHEMA IF EXISTS {{db}}.{{vault}};
USE ROLE USERADMIN;
ALTER USER {{ai_user}} UNSET DEFAULT_SECONDARY_ROLES, USE_CACHED_RESULT;

