-- masked_views.sql — the view inventory of the catalog, whether each view's definition is visible
-- to the capturing user (VIEW_DEFINITION is NULL unless the viewer owns the view), and whether a
-- visible definition shows a masking signal. An invisible definition is UNKNOWN, not "unmasked".
-- Read-only. Substitute ${catalog}.
SELECT v.table_catalog AS catalog, v.table_schema, v.table_name, 'VIEW' AS table_type,
       v.view_definition IS NOT NULL AS definition_visible,
       COALESCE(v.view_definition RLIKE '(?i)(sha1|sha2|md5|hash|mask|crc32|substr|left\\(|right\\(|regexp_replace)', false) AS has_masking_signal
FROM system.information_schema.views v
WHERE v.table_catalog = '${catalog}' AND v.table_schema <> 'information_schema'
ORDER BY v.table_schema, v.table_name;
