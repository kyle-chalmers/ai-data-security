-- ai_principals.sql — every principal holding a privilege in the catalog, with a hint of its
-- kind: a UUID is a service principal's applicationId, an address is a user, anything else a group
-- or the pseudo-groups `account users` / `users`. Helps the user name the AI principal.
-- Read-only.
SELECT grantee,
       CASE WHEN grantee RLIKE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN 'service_principal'
            WHEN grantee RLIKE '@' THEN 'user'
            WHEN grantee IN ('account users', 'users') THEN 'everyone'
            ELSE 'group' END AS principal_kind,
       COUNT(*) AS privilege_rows
FROM (
  SELECT grantee FROM system.information_schema.table_privileges WHERE table_catalog = '${catalog}'
  UNION ALL SELECT grantee FROM system.information_schema.schema_privileges WHERE catalog_name = '${catalog}'
  UNION ALL SELECT grantee FROM system.information_schema.catalog_privileges WHERE catalog_name = '${catalog}'
)
GROUP BY grantee
ORDER BY principal_kind, grantee;
