BigQuery pack (v0.9) — PARTIAL by design (ROADMAP: "explicit bindings only"). BigQuery access is
IAM: table/dataset bindings come from INFORMATION_SCHEMA.OBJECT_PRIVILEGES (explicit bindings only,
never inherited ones), so the pack ALSO records the project IAM policy, which is where inherited
read access usually lives. What it still cannot see is stated as UNKNOWN: folder/organization
bindings, Google Group membership, custom-role permissions, and Fine-Grained Reader grants on
policy-tag taxonomies.

Placeholders substituted by the skill after validation: `${project}` (`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`),
`${region}` (e.g. `us`, `eu`, `us-central1`; `^[a-z0-9-]+$`), `${dataset}` (`^[A-Za-z0-9_]+$`).
`--role` is the IAM member string exactly as bindings spell it: `serviceAccount:<email>`,
`user:<email>`, or `group:<email>`.

SQL files run through the user's own `bq` (Google SQL, CSV out). Every command runs under
`set -euo pipefail`, each object gets its own file, and a manifest of the dataset's tables is kept so
the evaluator can prove the capture is complete (a missing per-table file is a DB-06, not a clean row):

    set -euo pipefail
    P=<project>; R=<region>; D=<dataset>; M=<member-string>; E="${M#*:}"     # E = email part of --role
    sub() { sed -e "s/\${project}/$P/g" -e "s/\${region}/$R/g" -e "s/\${dataset}/$D/g" -e "s/\${table}/${1:-}/g" -e "s/\${principal_email}/$E/g"; }
    for f in pii_columns masked_views audit_logging; do sub < $f.sql | bq query --format=csv --nouse_legacy_sql --max_rows=100000 > <tmp>/$f.csv; done
    bq ls --format=csv --max_results=10000 "$P:$D" > <tmp>/tables_manifest.csv          # tableId,Type,... (the manifest)
    sub < grants_dataset.sql | bq query --format=csv --nouse_legacy_sql > <tmp>/grants.csv
    mkdir -p <tmp>/grants_by_table
    for t in $(tail -n +2 <tmp>/tables_manifest.csv | cut -d, -f1); do
      sub "$t" < grants_table.sql | bq query --format=csv --nouse_legacy_sql > "<tmp>/grants_by_table/$t.csv"   # fails loudly under set -e
      tail -n +2 "<tmp>/grants_by_table/$t.csv" >> <tmp>/grants.csv
    done

Non-SQL captures (JSON, via the user's own gcloud/bq):

    gcloud projects get-iam-policy "$P" --format=json > <tmp>/iam_policy.json
    gcloud iam policies list --attachment-point="cloudresourcemanager.googleapis.com/projects/$(gcloud projects describe "$P" --format='value(projectNumber)')" --kind=denypolicies --format=json > <tmp>/deny_policies.json
    gcloud logging buckets describe _Default --location=global --project="$P" --format=json > <tmp>/log_bucket.json
    [ "${M%%:*}" = serviceAccount ] && gcloud iam service-accounts keys list --iam-account="$E" --managed-by=user --format=json > <tmp>/sa_keys.json
    # policy tags AND data policies, recursing into nested fields (full field paths):
    { echo 'table_name,field_path,policy_tags,data_policies'
      for t in $(tail -n +2 <tmp>/tables_manifest.csv | cut -d, -f1); do
        bq show --schema --format=json "$P:$D.$t" | jq -r --arg t "$t" '
          def walk(prefix): .[] | (prefix + .name) as $p
            | (select((.policyTags.names // []) != [] or (.dataPolicies // []) != [])
               | [$t, $p, ((.policyTags.names // []) | join(";")), ((.dataPolicies // []) | map(.name) | join(";"))] | @csv),
              (select(.fields) | .fields | walk($p + "."));
          walk("")'
      done; } > <tmp>/policy_tags.csv
    for t in $(tail -n +2 <tmp>/tables_manifest.csv | cut -d, -f1); do bq ls --row_access_policies --format=json "$P:$D.$t"; done | jq -s 'add // []' > <tmp>/row_access_policies.json

Preconditions (stated at the gate): OBJECT_PRIVILEGES needs bigquery.datasets.get / bigquery.tables.getIamPolicy
on the objects; get-iam-policy needs resourcemanager.projects.getIamPolicy; INFORMATION_SCHEMA.JOBS needs
bigquery.jobs.listAll AND bigquery.jobs.create; deny policies need iam.denypolicies.list. BigQuery has no
read-only session switch; the CI lint on sql/bigquery/ is the guarantee.
