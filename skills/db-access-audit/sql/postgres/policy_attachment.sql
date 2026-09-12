-- policy_attachment.sql — which governed controls are actually ATTACHED to what the AI principal
-- can read: row-level security state per table, policies, masking labels (PostgreSQL Anonymizer
-- `anon` security labels), column-level grants, and which governance extensions exist at all.
-- Rows are (kind, name, detail). Read-only. Run with: psql --csv -f policy_attachment.sql
SELECT 'extension' AS kind, e.extname AS name, e.extversion AS detail
FROM pg_extension e
WHERE e.extname IN ('anon', 'pgaudit', 'postgres_fdw', 'dblink', 'file_fdw', 'pgcrypto')
UNION ALL
SELECT 'rls', n.nspname || '.' || c.relname,
       CASE WHEN c.relforcerowsecurity THEN 'forced'
            WHEN c.relrowsecurity THEN 'enabled' ELSE 'off' END
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
UNION ALL
SELECT 'policy', p.schemaname || '.' || p.tablename, p.policyname
FROM pg_policies p
UNION ALL
SELECT 'seclabel', n.nspname || '.' || c.relname || '.' || a.attname, s.provider
FROM pg_seclabel s
JOIN pg_class c ON c.oid = s.objoid AND s.classoid = 'pg_class'::regclass
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = s.objsubid
WHERE s.objsubid > 0
ORDER BY 1, 2, 3;
