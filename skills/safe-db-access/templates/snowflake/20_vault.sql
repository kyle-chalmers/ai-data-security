-- 2. KEY VAULT FOR PSEUDONYMIZATION -----------------------------------------------------------
-- A keyed SHA-256 replaces Confidential-tier identifiers so joins still work. The key is generated
-- inside Snowflake and stored in a schema the AI role has no USAGE on. The UDF runs with its
-- OWNER's rights, so callers never read the key. A salt table next to the data would not do this.
USE ROLE {{owner_role}};
CREATE SCHEMA IF NOT EXISTS {{db}}.{{vault}};
CREATE TABLE IF NOT EXISTS {{db}}.{{vault}}.KEYS (
    NAME        STRING PRIMARY KEY,
    KEY         STRING NOT NULL,
    CREATED_AT  TIMESTAMP_TZ NOT NULL DEFAULT CURRENT_TIMESTAMP()
);
INSERT INTO {{db}}.{{vault}}.KEYS (NAME, KEY)
SELECT 'pii', RANDSTR(64, RANDOM())
WHERE NOT EXISTS (SELECT 1 FROM {{db}}.{{vault}}.KEYS WHERE NAME = 'pii');
CREATE OR REPLACE FUNCTION {{db}}.{{vault}}.HASH_PII(V STRING)
RETURNS STRING
AS
$$
    SELECT IFF(V IS NULL, NULL, SHA2(CONCAT((SELECT KEY FROM {{db}}.{{vault}}.KEYS WHERE NAME = 'pii'), V), 256))
$$;

