-- schema_grants.sql — schema-level and SCOPED privileges. privilege_scope = TABLES means the grant
-- applies to every current AND future table in the schema: an indirect path (DB-07). Read-only.
SELECT namespace_name, privilege_type, privilege_scope, identity_name, identity_type, admin_option
FROM svv_schema_privileges
WHERE namespace_name NOT IN ('pg_catalog', 'information_schema', 'pg_internal')
ORDER BY namespace_name, identity_type, identity_name, privilege_scope, privilege_type;
