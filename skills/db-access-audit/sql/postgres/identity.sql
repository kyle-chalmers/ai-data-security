-- identity.sql — the AI principal's EFFECTIVE identity: role attributes, role memberships
-- (recursive, with INHERIT flags), objects it owns, and the access paths that widen it
-- silently: grants inherited through member roles, PUBLIC grants, and default privileges.
-- Rows are (kind, name, detail). Read-only. Run with: psql --csv -v ai_role='<role>' -f identity.sql
WITH RECURSIVE closure AS (
  SELECT r.oid AS role_oid, r.rolname, 0 AS depth, true AS inherits
  FROM pg_roles r WHERE r.rolname = :'ai_role'
  UNION
  SELECT g.oid, g.rolname, c.depth + 1,
         c.inherits AND COALESCE(m.inherit_option, true)
  FROM closure c
  JOIN pg_auth_members m ON m.member = c.role_oid
  JOIN pg_roles g ON g.oid = m.roleid
  WHERE c.depth < 16
)
SELECT 'attr' AS kind, a.name, a.value::text AS detail
FROM pg_roles r,
     LATERAL (VALUES ('rolsuper', r.rolsuper), ('rolbypassrls', r.rolbypassrls),
                     ('rolinherit', r.rolinherit), ('rolcreaterole', r.rolcreaterole),
                     ('rolcreatedb', r.rolcreatedb), ('rolreplication', r.rolreplication),
                     ('rolcanlogin', r.rolcanlogin)) AS a(name, value)
WHERE r.rolname = :'ai_role'
UNION ALL
SELECT 'member_of', c.rolname, CASE WHEN c.inherits THEN 'inherit' ELSE 'noinherit' END
FROM closure c WHERE c.depth > 0
UNION ALL
SELECT 'owns', n.nspname || '.' || cl.relname,
       CASE cl.relkind WHEN 'r' THEN 'table' WHEN 'p' THEN 'partitioned table'
                       WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized view' ELSE cl.relkind::text END
FROM pg_class cl
JOIN pg_namespace n ON n.oid = cl.relnamespace
JOIN pg_roles r ON r.oid = cl.relowner
WHERE r.rolname = :'ai_role' AND cl.relkind IN ('r', 'p', 'v', 'm')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
UNION ALL
SELECT 'inherited_grant', g.table_schema || '.' || g.table_name, c.rolname || ':' || g.privilege_type
FROM information_schema.role_table_grants g
JOIN closure c ON c.rolname = g.grantee AND c.depth > 0 AND c.inherits
WHERE g.table_schema NOT IN ('pg_catalog', 'information_schema')
UNION ALL
-- PUBLIC grants are read from the ACL itself: information_schema.role_table_grants omits them
-- unless the grantor happens to be an enabled role, which a least-privileged auditor is not.
SELECT 'public_grant', n.nspname || '.' || cl.relname, a.privilege_type
FROM pg_class cl
JOIN pg_namespace n ON n.oid = cl.relnamespace, LATERAL aclexplode(cl.relacl) a
WHERE a.grantee = 0 AND cl.relkind IN ('r', 'p', 'v', 'm')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
UNION ALL
SELECT 'default_acl',
       COALESCE(d.defaclnamespace::regnamespace::text, '<all schemas>') || ':' ||
       CASE d.defaclobjtype WHEN 'r' THEN 'tables' WHEN 'S' THEN 'sequences' WHEN 'f' THEN 'functions'
                            WHEN 'T' THEN 'types' WHEN 'n' THEN 'schemas' ELSE d.defaclobjtype::text END,
       -- grantor first: ALTER DEFAULT PRIVILEGES only edits the executing role's defaults, so the
       -- planner must say FOR ROLE <grantor> (v0.6)
       d.defaclrole::regrole::text || ':' || a.privilege_type
FROM pg_default_acl d, LATERAL aclexplode(d.defaclacl) a
JOIN pg_roles gr ON gr.oid = a.grantee
JOIN closure c ON c.rolname = gr.rolname
ORDER BY 1, 2, 3;
