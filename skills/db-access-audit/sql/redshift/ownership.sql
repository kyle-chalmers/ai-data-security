-- ownership.sql — who owns each relation. SVV_RELATION_PRIVILEGES lists explicit grants only; an
-- owner holds every privilege on its relation with no grant row, so ownership is write authority
-- (DB-01) and identity reach (DB-ID-01). Local catalog only (datashare objects are not here).
-- Read-only.
SELECT n.nspname AS schema_name, c.relname AS relation_name,
       CASE c.relkind WHEN 'r' THEN 'TABLE' WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' ELSE c.relkind::text END AS relation_type,
       u.usename AS owner
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_user u ON u.usesysid = c.relowner
WHERE c.relkind IN ('r', 'v', 'm')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_internal')
ORDER BY n.nspname, c.relname;
