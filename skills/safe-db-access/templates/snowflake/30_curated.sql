-- 3. CURATED SCHEMA OF SECURE VIEWS -------------------------------------------------------------
-- Secure views hide their definition and evaluate with the OWNER's privileges. Restricted-tier
-- columns are EXCLUDEd; Confidential-tier columns are replaced by their keyed hash.
USE ROLE {{owner_role}};
CREATE SCHEMA IF NOT EXISTS {{db}}.{{curated}};
{{views}}
