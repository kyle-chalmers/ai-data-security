-- grants_dataset.sql — access control bindings EXPLICITLY set on the dataset itself (they apply to
-- every table in it). OBJECT_PRIVILEGES must be filtered to ONE dataset (object_name) or ONE
-- table (object_schema + object_name); inherited project/folder/org bindings are never listed —
-- iam_policy.json covers the project level. Read-only. Substitute ${project}, ${region}, ${dataset}.
SELECT object_catalog, object_schema, object_name, object_type, privilege_type, grantee
FROM `${project}`.`region-${region}`.INFORMATION_SCHEMA.OBJECT_PRIVILEGES
WHERE object_name = '${dataset}'
ORDER BY grantee, privilege_type;
