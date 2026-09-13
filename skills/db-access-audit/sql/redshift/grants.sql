-- grants.sql — every relation privilege explicitly granted in the current database, with the
-- relation's type. The evaluator keeps rows for the AI user, the roles it holds (transitively),
-- the groups it is in, and PUBLIC. Visible in full only to superusers / SYSLOG ACCESS UNRESTRICTED
-- (otherwise a partial result — identity.csv records the auditor's own standing). Read-only.
SELECT p.namespace_name, p.relation_name, t.table_type, p.privilege_type,
       p.identity_name, p.identity_type, p.admin_option
FROM svv_relation_privileges p
LEFT JOIN svv_tables t
  ON t.table_schema = p.namespace_name AND t.table_name = p.relation_name
WHERE p.namespace_name NOT IN ('pg_catalog', 'information_schema', 'pg_internal')
ORDER BY p.namespace_name, p.relation_name, p.identity_type, p.identity_name, p.privilege_type;
