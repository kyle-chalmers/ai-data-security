-- external_paths.sql — paths outside the local database: external schemas (Spectrum / Glue data
-- catalog, Hive, federated Postgres/MySQL, remote Redshift, Kinesis, MSK) and the IAM role each
-- carries, joined to who holds USAGE on them (only USAGE is reach; other privileges are shown for
-- context). COPY/UNLOAD IAM grants are in iam_privileges.csv. Read-only.
SELECT e.schemaname AS schema_name,
       CASE e.eskind WHEN 1 THEN 'data_catalog' WHEN 2 THEN 'hive_metastore' WHEN 3 THEN 'federated_postgres'
                     WHEN 4 THEN 'local_redshift' WHEN 5 THEN 'remote_redshift' WHEN 8 THEN 'federated_mysql'
                     WHEN 9 THEN 'kinesis' WHEN 10 THEN 'msk' ELSE 'other_' || e.eskind::text END AS kind,
       e.databasename AS external_database,
       COALESCE(p.identity_name, '') AS identity_name, COALESCE(p.identity_type, '') AS identity_type,
       COALESCE(p.privilege_type, '') AS privilege_type
FROM svv_external_schemas e
LEFT JOIN svv_schema_privileges p ON p.namespace_name = e.schemaname
ORDER BY e.schemaname, p.identity_type, p.identity_name;
