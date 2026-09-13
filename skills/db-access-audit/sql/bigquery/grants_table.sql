-- grants_table.sql — access control bindings EXPLICITLY set on ONE table or view (the view requires
-- object_schema AND object_name). The skill runs it once per table in the dataset and concatenates
-- the CSVs (header once) into grants.csv. Read-only. Substitute ${project}, ${region}, ${dataset}, ${table}.
SELECT object_catalog, object_schema, object_name, object_type, privilege_type, grantee
FROM `${project}`.`region-${region}`.INFORMATION_SCHEMA.OBJECT_PRIVILEGES
WHERE object_schema = '${dataset}' AND object_name = '${table}'
ORDER BY grantee, privilege_type;
