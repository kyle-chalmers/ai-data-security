FIXTURE — recorded `dbsqlcli --table-format csv` outputs of the Databricks pack against an invented
Unity Catalog metastore: catalog `analytics`, schema `app`, tables `customers` (PII) and `orders`.
The AI principal is a HUMAN user (`ai-agent@example.invalid`) — the identity mistake the audit
should flag — who is a direct member of `analysts` (which holds MANAGE on schema `app`) and, through
nesting, of `all-data-readers` (catalog-level SELECT and READ VOLUME). The human owns the external
table `app.orders`. A service principal `3f1c…` holds SELECT on `app.orders` but no USE SCHEMA
(a latent grant).
Values are invented; shapes mirror system.information_schema. No data rows exist anywhere.
