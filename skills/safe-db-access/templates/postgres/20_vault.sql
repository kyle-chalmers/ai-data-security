-- 2. KEY VAULT FOR PSEUDONYMIZATION -----------------------------------------------------------
-- A keyed hash (HMAC-SHA-256, pgcrypto) replaces Confidential-tier identifiers so joins still
-- work. The key is generated on the server and stored where only DBAs and the view owner can
-- reach it. A salt table in the same schema as the data would NOT do this: the agent could read it.
-- pgcrypto is referenced as public.* on purpose (no search_path guessing). If your pgcrypto lives in
-- another schema, change "public." below to that schema before running; the planner does not guess.
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
CREATE SCHEMA IF NOT EXISTS {{vault}};
REVOKE ALL ON SCHEMA {{vault}} FROM PUBLIC;
CREATE TABLE IF NOT EXISTS {{vault}}.keys (
    name        text PRIMARY KEY,
    key         bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON {{vault}}.keys FROM PUBLIC;
INSERT INTO {{vault}}.keys (name, key)
SELECT 'pii', public.gen_random_bytes(32)
WHERE NOT EXISTS (SELECT 1 FROM {{vault}}.keys WHERE name = 'pii');
-- SECURITY DEFINER: runs as the DBA who creates it, so callers never see the key.
CREATE OR REPLACE FUNCTION {{vault}}.hash_pii(value text) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, {{vault}}
AS $$
    SELECT CASE WHEN value IS NULL THEN NULL
                ELSE encode(public.hmac(convert_to(value, 'UTF8'), (SELECT k.key FROM {{vault}}.keys k WHERE k.name = 'pii'), 'sha256'::text), 'hex')
           END
$$;
REVOKE ALL ON FUNCTION {{vault}}.hash_pii(text) FROM PUBLIC;
-- Only the curated view owner may call it (section 3 creates the views under that role). CREATE
-- ROLE fails if {{owner_role}} already exists: that is deliberate, the rollback drops this role.
CREATE ROLE {{owner_role}} NOLOGIN NOINHERIT;
GRANT USAGE ON SCHEMA {{vault}} TO {{owner_role}};
GRANT EXECUTE ON FUNCTION {{vault}}.hash_pii(text) TO {{owner_role}};

