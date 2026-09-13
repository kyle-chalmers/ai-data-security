-- external_paths.sql — privileges on securables that reach OUTSIDE Unity Catalog tables: external
-- locations (cloud storage paths), storage credentials, and volumes (files). WRITE FILES / WRITE
-- VOLUME / CREATE EXTERNAL * are exfiltration paths; READ FILES / READ VOLUME bypass table-level
-- masking. Read-only.
SELECT 'EXTERNAL_LOCATION' AS kind, e.external_location_name AS name, e.grantee, e.privilege_type, COALESCE(e.inherited_from, 'NONE') AS inherited_from
FROM system.information_schema.external_location_privileges e
UNION ALL
SELECT 'STORAGE_CREDENTIAL', s.storage_credential_name, s.grantee, s.privilege_type, COALESCE(s.inherited_from, 'NONE')
FROM system.information_schema.storage_credential_privileges s
UNION ALL
SELECT 'VOLUME', v.volume_catalog || '.' || v.volume_schema || '.' || v.volume_name, v.grantee, v.privilege_type, COALESCE(v.inherited_from, 'NONE')
FROM system.information_schema.volume_privileges v
WHERE v.volume_catalog = '${catalog}'
ORDER BY kind, name, grantee, privilege_type;
