-- audit_logging.sql — is the audit trail readable by anyone but admins? Lists the system schemas
-- that exist (access = audit log + lineage, query = query history) and every grant on them. With
-- no grants, only account/metastore admins can read system.access.audit or system.query.history;
-- statement_text is redacted for non-admins anyway. Retention is 365 days.
-- Read-only.
SELECT 'system_schema' AS kind, s.schema_name AS name, '' AS detail
FROM system.information_schema.schemata s
WHERE s.catalog_name = 'system' AND s.schema_name IN ('access', 'query')
UNION ALL
SELECT 'grant', p.schema_name, p.grantee || ':' || p.privilege_type
FROM system.information_schema.schema_privileges p
WHERE p.catalog_name = 'system' AND p.schema_name IN ('access', 'query')
ORDER BY kind, name, detail;
