-- 3b. MASKING POLICY ON THE RAW TABLES (defense in depth; Enterprise or higher) -----------------
{{edition_note}}
-- Even if a future grant reaches the raw table, an agent-marked session or the AI role sees NULL.
-- IS_AGENT_ACTIVATED() is true in sessions of a SERVICE_AGENT identity; CURRENT_ROLE() covers a
-- plain SERVICE user. Everyone else keeps seeing the value, so nothing breaks for people.
USE ROLE {{owner_role}};
CREATE MASKING POLICY IF NOT EXISTS {{db}}.{{curated}}.MASK_FOR_AGENTS AS (VAL STRING) RETURNS STRING ->
  CASE WHEN IS_AGENT_ACTIVATED() OR CURRENT_ROLE() = '{{ai_role}}' THEN NULL ELSE VAL END;
{{attach}}
