-- column_grants.sql — column-level SELECT / UPDATE grants. These have no relation-level row in
-- SVV_RELATION_PRIVILEGES, so a user granted only SELECT(ssn) is invisible to grants.sql; here it
-- is a direct PII read path (DB-03 / DB-08) or write (DB-01). Read-only.
SELECT namespace_name, relation_name, column_name, privilege_type, identity_name, identity_type
FROM svv_column_privileges
WHERE namespace_name NOT IN ('pg_catalog', 'information_schema', 'pg_internal')
ORDER BY namespace_name, relation_name, column_name, identity_type, identity_name, privilege_type;
