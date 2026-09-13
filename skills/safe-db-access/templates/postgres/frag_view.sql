CREATE OR REPLACE VIEW {{curated}}.{{view}} AS
SELECT
{{body}}
FROM {{schema}}.{{table}};
ALTER VIEW {{curated}}.{{view}} OWNER TO {{owner_role}};

