-- masked_views.sql — every table and view in the dataset with its type, and for views whether the
-- definition shows a masking signal. Read-only.
SELECT t.table_schema, t.table_name, t.table_type,
       v.view_definition IS NOT NULL AS definition_visible,
       COALESCE(REGEXP_CONTAINS(LOWER(v.view_definition), r'(sha256|sha512|md5|farm_fingerprint|hash|mask|substr|left\(|right\(|regexp_replace|to_hex)'), FALSE) AS has_masking_signal
FROM `${project}`.`${dataset}`.INFORMATION_SCHEMA.TABLES t
LEFT JOIN `${project}`.`${dataset}`.INFORMATION_SCHEMA.VIEWS v
  ON v.table_schema = t.table_schema AND v.table_name = t.table_name
ORDER BY t.table_name;
