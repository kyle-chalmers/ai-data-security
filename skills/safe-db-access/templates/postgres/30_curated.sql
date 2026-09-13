-- 3. CURATED SCHEMA OF MASKED VIEWS ------------------------------------------------------------
-- Views run with their OWNER's privileges (security_invoker is off), so the AI role needs SELECT
-- on the view only. Restricted-tier columns are omitted entirely; Confidential-tier columns are
-- replaced by their keyed hash; everything else passes through by name.
CREATE SCHEMA IF NOT EXISTS {{curated}} AUTHORIZATION {{owner_role}};
{{grant_owner_reads}}
{{views}}
