-- masked_views.sql — the view inventory and whether each definition shows a masking signal
-- (pg_class + pg_get_viewdef, both available in Redshift's PostgreSQL-derived catalog). Read-only.
SELECT n.nspname AS table_schema, c.relname AS table_name,
       (LOWER(pg_get_viewdef(c.oid, true)) ~ '(md5|sha1|sha2|fnv_hash|hash|mask|substring|left\\(|right\\(|regexp_replace)') AS has_masking_signal
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'v'
  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_internal')
ORDER BY n.nspname, c.relname;
