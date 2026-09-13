-- columns.sql — every column of every non-system table (v0.6). Not a finding input: the
-- safe-db-access planner needs the full column list of each table the AI role reads so a curated
-- view can name its columns explicitly (Postgres has no SELECT * EXCLUDE). Names and types only.
-- Read-only. Run with: psql --csv -f columns.sql
SELECT c.table_schema,
       c.table_name,
       c.column_name,
       c.data_type,
       c.ordinal_position
FROM information_schema.columns c
JOIN information_schema.tables t
  ON t.table_schema = c.table_schema AND t.table_name = c.table_name
WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema')
  AND t.table_type = 'BASE TABLE'
ORDER BY c.table_schema, c.table_name, c.ordinal_position;
