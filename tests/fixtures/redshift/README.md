FIXTURE — recorded `psql --csv` outputs of the Redshift pack against an invented cluster: schema
`app` with `customers` (PII) and `orders`, a Spectrum external schema `lake`, and the AI user
`ai_agent` — a password user (no IAM: prefix) that holds role `analyst` (which itself holds
`reporting`), is in group `bi_users`, and has direct INSERT/UPDATE on `app.customers`. A masking
policy is attached to `app.customers.email` but only for role `hr`, so it does nothing for the
agent, while a PUBLIC policy masks `full_name` for everyone. The agent also owns `app.scratch_exports`, holds
column-level SELECT on `hr.employees(ssn, salary)` with no relation grant, and role `analyst` may UNLOAD via
the default IAM role. The capture ran as a superuser, so grant and policy views are complete. Values
invented; no data.
