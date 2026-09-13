AWS Lake Formation pack (v0.11) — recorded JSON from the user's own AWS CLI; no SQL. `--role` is the
IAM principal ARN exactly as Lake Formation spells it (arn:aws:iam::<acct>:role/<name> or :user/<name>,
or a SAML / Identity Center ARN). Captures:

    aws lakeformation list-permissions --principal DataLakePrincipalIdentifier=<arn> --output json > <tmp>/permissions.json
    aws lakeformation list-permissions --output json --max-results 1000 > <tmp>/all_permissions.json   # IAMAllowedPrincipals / ALLIAMPrincipals / groups
    aws lakeformation get-data-lake-settings --output json > <tmp>/settings.json
    aws lakeformation list-data-cells-filter --output json > <tmp>/data_cells_filters.json
    for db in <db1> <db2>; do aws glue get-tables --database-name "$db" --output json; done \
      | jq -s '{TableList: [.[].TableList[]]}' > <tmp>/tables.json                                        # every database of interest; NOT jq -s 'add' (it keeps one list)
    aws lakeformation list-resources --output json > <tmp>/resources.json                                # registered S3 locations (hybrid access mode flag)
    aws iam list-attached-role-policies --role-name <name> --output json > <tmp>/iam_policies.json         # --role is a role; for a user: list-attached-user-policies
    aws lakeformation list-lake-formation-opt-ins --output json > <tmp>/opt_ins.json                       # required when any location is in hybrid access mode, else DB-06
    aws cloudtrail describe-trails --output json > <tmp>/cloudtrail.json                                   # required for DB-05, else the audit trail is DB-06

Preconditions (stated at the gate): the capturing identity needs lakeformation:ListPermissions,
GetDataLakeSettings, ListDataCellsFilter, ListResources, ListLakeFormationOptIns, glue:GetTables,
iam:ListAttachedRolePolicies, cloudtrail:DescribeTrails. list-permissions returns ONLY explicitly
granted permissions (with both --principal and --resource it returns effective ones); grants to
IAMAllowedPrincipals / ALLIAMPrincipals mean IAM alone governs the resource. LF-tag-based grants
(LFTagPolicy / LFTag / LFTagExpression) and conditional grants are NOT resolved: when the principal
holds any, the report says so as DB-06 and does not count those tables. A data cells filter counts as
protection only when granted with SELECT and present in data_cells_filters.json. Hybrid access mode is
judged per principal: tables under a hybrid location where this principal is not opted in are governed
by its IAM S3 permissions (DB-07); without opt_ins.json that is DB-06. What Lake Formation cannot see —
whether the principal's IAM policies grant s3:GetObject on the table locations directly — is evaluated
from iam_policies.json by AWS-managed policy NAME only (AmazonS3FullAccess, AmazonS3ReadOnlyAccess,
ReadOnlyAccess, PowerUserAccess, AdministratorAccess); inline, customer and group policies, permission
boundaries, SCPs and bucket policies are always reported UNKNOWN. Athena / Redshift Spectrum query
text is not in CloudTrail; Redshift federated catalogs emit no GetDataAccess.
