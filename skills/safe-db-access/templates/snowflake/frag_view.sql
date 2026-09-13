CREATE OR REPLACE SECURE VIEW {{db}}.{{curated}}.{{view}} AS
SELECT
{{omitted}}    *{{exclude}}{{hashed}}
FROM {{db}}.{{schema}}.{{table}};

