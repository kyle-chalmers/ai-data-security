-- databases.sql — every attached database: other local files, remote (https/s3) attachments, MotherDuck
-- (md:) shares. type/readonly tell whether the agent can write there. Read-only.
SELECT database_name, path, type, readonly, internal FROM duckdb_databases() WHERE NOT internal ORDER BY database_name;
