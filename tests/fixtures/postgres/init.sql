-- FIXTURE — a deliberately misconfigured database for db-access-audit tests.
-- The ai_agent role is everything the audit should flag: write privileges, SELECT on raw
-- base tables with PII columns, no masked-view layer, no audit logging configured.
-- The password is an inert fixture placeholder for a throwaway container.

CREATE SCHEMA app;

CREATE TABLE app.customers (
    customer_id  integer PRIMARY KEY,
    full_name    text,
    email        text,
    ssn          text,
    card_number  text,
    member_ssn   text,        -- token-boundary match: prefixed Restricted name
    customer_email text,      -- token-boundary match: prefixed Confidential name
    emailed_at   timestamptz, -- must NOT match: 'email' is not a whole token here
    balance      numeric(12, 2)
);

CREATE TABLE app.orders (
    order_id     integer PRIMARY KEY,
    customer_id  integer REFERENCES app.customers (customer_id),
    total        numeric(12, 2)
);

CREATE ROLE ai_agent LOGIN PASSWORD 'fixture-placeholder';

GRANT USAGE ON SCHEMA app TO ai_agent;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA app TO ai_agent;
