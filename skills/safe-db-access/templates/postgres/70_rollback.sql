-- 7. ROLLBACK — restores the INSECURE state the audit found. Keep for emergencies only. -----------
-- Scope: exactly the objects and grants sections 1-5 created. {{owner_role}} must be the role this
-- plan created (section 2 refuses to run if it already existed), so dropping it removes nothing else.
DROP SCHEMA IF EXISTS {{curated}} CASCADE;
DROP SCHEMA IF EXISTS {{vault}} CASCADE;
{{revoke_owner_reads}}DROP ROLE IF EXISTS {{owner_role}};
ALTER ROLE {{ai_role}} INHERIT CONNECTION LIMIT -1;
ALTER ROLE {{ai_role}} RESET log_statement;
ALTER ROLE {{ai_role}} RESET log_min_duration_statement;
{{regrant_memberships}}{{regrant_selects}}{{regrant_writes}}{{regrant_default_acl}}{{regrant_public}}
