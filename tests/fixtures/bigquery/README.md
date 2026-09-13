FIXTURE — recorded `bq --format=csv` and `gcloud --format=json` outputs of the BigQuery pack against an
invented project `acme-analytics` / dataset `app`, region `us`. The AI principal is a service account
`serviceAccount:ai-agent@acme-analytics.iam.gserviceaccount.com` that holds roles/bigquery.dataViewer at
PROJECT level (inherited by every dataset — invisible in OBJECT_PRIVILEGES), roles/bigquery.jobUser,
roles/storage.objectCreator (an export path), and has one user-managed key, and is bound to a custom role (permissions not expanded). A human
`user:contractor@example.invalid` holds project-level dataViewer with no jobUser role (latent). The dataset has an explicit
dataEditor binding for the agent on `customers`, a policy tag on `customers.ssn` only, one view without a
masking signal, and an external table. A CONDITIONAL dataOwner binding
(office hours) exists for the agent and must be excluded from effective grants; a group has a table-level
binding on customers (membership unknown); `contact` is a STRUCT whose nested email/phone are PII, with a
data policy on contact.phone. Values invented; no data rows exist.
