-- database_grants.sql — database-level and database-SCOPED privileges. privilege_scope = TABLES
-- means the grant applies to every current and future table in every schema of the database;
-- SCHEMAS scope with USAGE means every schema is usable. Both are indirect paths (DB-07). Read-only.
SELECT database_name, privilege_type, privilege_scope, identity_name, identity_type, admin_option
FROM svv_database_privileges
WHERE database_name = current_database()
ORDER BY identity_type, identity_name, privilege_scope, privilege_type;
