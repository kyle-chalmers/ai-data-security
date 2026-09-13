-- grants.sql — every privilege on the catalog, its schemas, and its tables/views, with the object's
-- type and owner (table, schema, or catalog owner: owners manage grants on everything below). eval_grants filters to the AI principal AND the groups identity.sql returns,
-- because Unity Catalog grants to a group apply to every member and catalog/schema-level grants
-- apply to every current and future child object (INHERITED_FROM names the ancestor).
-- Read-only. Substitute ${catalog}.
SELECT 'TABLE' AS level, p.table_catalog AS catalog, p.table_schema AS schema_name, p.table_name AS object_name,
       t.table_type AS object_type, t.table_owner AS owner, p.grantee, p.privilege_type, COALESCE(p.inherited_from, 'NONE') AS inherited_from
FROM system.information_schema.table_privileges p
JOIN system.information_schema.tables t
  ON t.table_catalog = p.table_catalog AND t.table_schema = p.table_schema AND t.table_name = p.table_name
WHERE p.table_catalog = '${catalog}'
UNION ALL
SELECT 'SCHEMA', s.catalog_name, s.schema_name, NULL, 'SCHEMA', sc.schema_owner, s.grantee, s.privilege_type, COALESCE(s.inherited_from, 'NONE')
FROM system.information_schema.schema_privileges s
LEFT JOIN system.information_schema.schemata sc ON sc.catalog_name = s.catalog_name AND sc.schema_name = s.schema_name
WHERE s.catalog_name = '${catalog}'
UNION ALL
SELECT 'CATALOG', c.catalog_name, NULL, NULL, 'CATALOG', ca.catalog_owner, c.grantee, c.privilege_type, COALESCE(c.inherited_from, 'NONE')
FROM system.information_schema.catalog_privileges c
LEFT JOIN system.information_schema.catalogs ca ON ca.catalog_name = c.catalog_name
WHERE c.catalog_name = '${catalog}'
ORDER BY level, schema_name, object_name, grantee, privilege_type;
