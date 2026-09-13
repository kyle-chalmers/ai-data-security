-- policy_attachment.sql — column masks and row filters attached to tables in the catalog.
-- eval_grants joins column masks to the PII columns the principal can read (DB-08). ABAC
-- policies' exempt principals are not visible here; the report says so.
-- Read-only. Substitute ${catalog}.
SELECT 'column_mask' AS kind, m.catalog_name AS catalog, m.schema_name AS table_schema, m.table_name, m.column_name,
       m.mask_catalog || '.' || m.mask_schema || '.' || m.mask_name AS policy_name
FROM system.information_schema.column_masks m
WHERE m.catalog_name = '${catalog}'
UNION ALL
SELECT 'row_filter', f.catalog_name, f.schema_name, f.table_name, NULL,
       f.filter_catalog || '.' || f.filter_schema || '.' || f.filter_name
FROM system.information_schema.row_filters f
WHERE f.catalog_name = '${catalog}'
ORDER BY kind, table_schema, table_name, column_name;
