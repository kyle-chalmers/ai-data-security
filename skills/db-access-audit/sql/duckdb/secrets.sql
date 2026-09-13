-- secrets.sql — secrets visible to the session (values redacted by DuckDB itself): persistent secrets are
-- stored UNENCRYPTED under secret_directory; a temporary secret lives only in memory. Read-only.
-- The CLI prints nothing (not even the header) for an empty result, which the evaluator would have to
-- treat as a failed capture; the '(none)' sentinel row keeps the header and is dropped by the evaluator.
SELECT name, type, provider, persistent::VARCHAR AS persistent, storage, scope::VARCHAR AS scope FROM duckdb_secrets()
UNION ALL
SELECT '(none)', '', '', 'false', '', '' WHERE NOT EXISTS (SELECT 1 FROM duckdb_secrets())
ORDER BY 1;
