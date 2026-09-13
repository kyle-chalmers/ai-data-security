-- 4. GRANTS: RAW OUT, CURATED IN ---------------------------------------------------------------
USE ROLE SECURITYADMIN;
-- Direct grants on raw schemas (DB-01 / DB-02 / DB-03):
{{revoke_raw}}-- Paths outside the database (DB-10):
{{revoke_external}}-- The only read surface the AI role keeps:
GRANT USAGE ON DATABASE {{db}} TO ROLE {{ai_role}};
GRANT USAGE ON SCHEMA {{db}}.{{curated}} TO ROLE {{ai_role}};
GRANT SELECT ON ALL VIEWS IN SCHEMA {{db}}.{{curated}} TO ROLE {{ai_role}};
GRANT SELECT ON FUTURE VIEWS IN SCHEMA {{db}}.{{curated}} TO ROLE {{ai_role}};

