-- masked_views.sql — views and whether their SQL shows a masking-LOOKING expression (a substring hint, never proof
-- that PII is transformed: the evaluator reports signals as UNKNOWN, not as a masked layer). Read-only. '(none)' sentinel keeps
-- the CSV header when there are no views (the CLI prints nothing for an empty result).
SELECT database_name, schema_name, view_name,
       regexp_matches(lower(sql), '(md5|sha256|sha1|hash|mask|substr|left\(|right\(|regexp_replace)')::VARCHAR AS has_masking_signal
FROM duckdb_views() WHERE NOT internal
UNION ALL
SELECT '(none)', '', '', 'false' WHERE NOT EXISTS (SELECT 1 FROM duckdb_views() WHERE NOT internal)
ORDER BY 1, 2, 3;
