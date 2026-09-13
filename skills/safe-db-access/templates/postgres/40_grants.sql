-- 4. GRANTS: RAW OUT, CURATED IN ---------------------------------------------------------------
-- Direct grants (DB-01 / DB-02 / DB-03):
{{revoke_raw}}-- Default privileges that would re-grant future objects automatically (DB-07). ALTER DEFAULT
-- PRIVILEGES edits one grantor's defaults, hence FOR ROLE <the role the audit saw as grantor>:
{{revoke_default_acl}}-- PUBLIC grants (DB-07). These affect EVERY role in the database, not just the AI role, so they are
-- rendered commented out unless the planner was run with --include-public-revokes after review:
{{revoke_public}}-- The only read surface the AI role keeps:
GRANT USAGE ON SCHEMA {{curated}} TO {{ai_role}};
GRANT SELECT ON ALL TABLES IN SCHEMA {{curated}} TO {{ai_role}};

