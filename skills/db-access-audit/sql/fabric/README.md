Microsoft Fabric Warehouse / SQL analytics endpoint pack (v0.10). T-SQL over the SQL connection string
(TDS, port 1433, Microsoft Entra authentication only — SQL authentication is not supported). Capture
each file as CSV with the user's own sqlcmd (Entra interactive or service-principal login):

    sqlcmd -S <workspace>.datawarehouse.fabric.microsoft.com -d <warehouse> -G -i <file>.sql \
      -s "," -W -h -1 -f 65001 -o <tmp>/<file>.csv

(`-h -1` suppresses the header row and the dashes line; each pack file therefore SELECTs its header
as a first UNION ALL row so the CSV is self-describing. `-W` trims padding, `-s ","` sets the separator.)

`--role` is the database principal NAME as sys.database_principals spells it: an Entra user's UPN, a
service principal's display name, or an Entra group's name. The skill validates it against
`^[A-Za-z0-9._@ -]{1,128}$` (no quotes, semicolons, or `--`) BEFORE substituting `${principal}`.

Also capture, when the item is a Lakehouse SQL analytics endpoint, its access mode (Fabric REST / portal):

    { "itemType": "SQLEndpoint", "accessMode": "delegated" | "userIdentity" }  > <tmp>/endpoint_mode.json
    { "itemType": "Warehouse" }                                                 > <tmp>/endpoint_mode.json   (warehouses)

In OneLake user-identity mode, table SQL grants are ignored and OneLake security roles govern access;
the evaluator then reports every table-access check as UNKNOWN instead of a verdict.

Eight pack files: principals, role_members, grants, ownership, modules, pii_columns, masked_views,
audit_logging. Optional JSON capture of the warehouse's SQL audit log setting (Fabric REST API, needs a bearer token
and the Audit permission; see configure-sql-audit-logs):

    GET https://api.fabric.microsoft.com/v1/workspaces/<workspaceId>/warehouses/<warehouseId>/settings/sqlAudit  > <tmp>/audit_status.json

Preconditions (stated at the gate): SQL permissions are only HALF the model — workspace roles Admin,
Member, and Contributor have CONTROL (read/write everything, unmasked) and even Viewer has ReadData
(reads every table and view); item permissions (Read / ReadData / ReadAll) grant access outside SQL.
Only a principal with item Read but no ReadData and no workspace role is bound by SQL GRANT/DENY.
None of this is visible from T-SQL, so the pack records what the connection can see and the
evaluator states the rest as UNKNOWN. sys.database_permissions shows other users' rows only with VIEW
DEFINITION / ALTER ANY USER (VIEW SECURITY DEFINITION); capture with an Admin/Member identity. No
read-only session switch exists; the CI lint on sql/fabric/ is the guarantee.
