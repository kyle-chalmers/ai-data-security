"""AWS Lake Formation — recorded AWS CLI JSON (see sql/lakeformation/README.md). No SQL.

Identity model: the AI principal is an IAM role or user ARN (or SAML / Identity Center identity).
Lake Formation permissions are explicit grants on Catalog / Database / Table / TableWithColumns /
DataLocation / LF-Tag policy resources; `IAMAllowedPrincipals` Super on a resource means IAM alone
governs it (every principal with Glue+S3 IAM permissions reads it); `ALLIAMPrincipals` grants to
every principal in the account. Column filtering comes from TableWithColumns (inclusion) or
ColumnWildcard.ExcludedColumnNames (exclusion) and from data cells filters granted with SELECT.
Effective access is the union of named-resource grants and LF-tag-based (LF-TBAC) grants; this
module does not resolve tag assignments, so any LF-tag / tag-expression / conditional grant on the
principal is reported as DB-06 rather than assumed harmless. Hybrid access mode is judged per
principal from list-lake-formation-opt-ins.
"""

import re

READ = {"SELECT", "ALL", "SUPER_USER"}
WRITE = {"INSERT", "DELETE", "ALTER", "DROP", "ALL", "SUPER_USER", "CREATE_TABLE", "CREATE_DATABASE"}
# Judged by NAME only, and only names whose documents grant s3:GetObject / s3:* on arbitrary buckets.
# AWSGlueConsoleFullAccess (s3 scoped to Glue-named paths) and AWSLakeFormationDataAdmin (bucket
# metadata actions) do NOT belong here; they fall through to the by-name DB-06 like customer policies.
ADMIN_POLICIES = {"AdministratorAccess", "PowerUserAccess", "AmazonS3FullAccess"}
S3_READ_POLICIES = {"AmazonS3ReadOnlyAccess", "AmazonS3FullAccess", "ReadOnlyAccess", "PowerUserAccess", "AdministratorAccess"}
ARN_KIND = re.compile(r"^arn:aws:iam::\d{12}:(role|user)/")

PACK = {}
JSON_INPUTS = {
    "permissions": "aws lakeformation list-permissions --principal DataLakePrincipalIdentifier=<arn> --output json",
    "all_permissions": "aws lakeformation list-permissions --output json --max-results 1000",
    "settings": "aws lakeformation get-data-lake-settings --output json",
    "data_cells_filters": "aws lakeformation list-data-cells-filter --output json",
    "tables": "aws glue get-tables --database-name <db> --output json, one per database, merged with jq -s '{TableList: [.[].TableList[]]}'",
    "resources": "aws lakeformation list-resources --output json",
    "iam_policies": "aws iam list-attached-role-policies --role-name <name> --output json (or list-attached-user-policies)",
    "opt_ins": "aws lakeformation list-lake-formation-opt-ins --output json (needed when any registered location is in hybrid access mode)",
    "cloudtrail": "aws cloudtrail describe-trails --output json (needed for DB-05; without it the audit trail is UNKNOWN)",
}
OPTIONAL_JSON_INPUTS = {"opt_ins", "cloudtrail"}
CAPTURE = "see JSON_INPUTS (AWS CLI, --output json)"
PRECONDITION = ("list-permissions returns explicitly granted permissions only; grants to IAMAllowedPrincipals / ALLIAMPrincipals hand "
                "control to IAM; LF-tag-based grants are not resolved (reported as DB-06 when present); whether the principal's IAM policies "
                "grant S3 access to table locations directly is judged by AWS-managed policy NAME only (inline, customer, group policies, "
                "permission boundaries, SCPs and bucket policies are not expanded and are always reported as DB-06).")

PII_TOKENS = re.compile(r"(^|_)(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?|card_number|pan|cvv|account_number|routing_number|dob|birth_date|date_of_birth|diagnosis|medical|email|phone|mobile|address|first_name|last_name|full_name|ip_address|salary|income)(_|$)", re.I)
RESTRICTED = re.compile(r"(^|_)(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?|card_number|pan|cvv|account_number|routing_number|dob|birth_date|date_of_birth|diagnosis|medical)(_|$)", re.I)


def _kind(arn):
    m = ARN_KIND.match(arn or "")
    if m:
        return m.group(1)
    if "saml-provider" in (arn or ""):
        return "saml"
    if "identitystore" in (arn or ""):
        return "identity_center"
    if (arn or "").upper() in ("IAM_ALLOWED_PRINCIPALS", "IAMALLOWEDPRINCIPALS"):
        return "iam_allowed_principals"
    return "unknown"


def _res(r):
    """(kind, database, table, columns_included, columns_excluded, extra) for one Resource block."""
    r = r or {}
    if "TableWithColumns" in r:
        t = r["TableWithColumns"]
        return ("table", t.get("DatabaseName"), t.get("Name"), list(t.get("ColumnNames") or []), list((t.get("ColumnWildcard") or {}).get("ExcludedColumnNames") or []), "")
    if "Table" in r:
        t = r["Table"]
        return ("table" if not t.get("TableWildcard") and t.get("Name") else "all_tables", t.get("DatabaseName"), t.get("Name") or "*", None, None, "")
    if "Database" in r:
        return ("database", r["Database"].get("Name"), None, None, None, "")
    if "Catalog" in r:
        return ("catalog", None, None, None, None, "")
    if "DataLocation" in r:
        return ("data_location", None, None, None, None, r["DataLocation"].get("ResourceArn", ""))
    if "LFTagPolicy" in r:
        p = r["LFTagPolicy"]
        return ("lf_tag_policy", None, None, None, None, f"{p.get('ResourceType', '')}:{p.get('ExpressionName') or p.get('Expression')}")
    if "DataCellsFilter" in r:
        f = r["DataCellsFilter"]
        return ("data_cells_filter", f.get("DatabaseName"), f.get("TableName"), None, None, f.get("Name", ""))
    if "LFTag" in r:
        g = r["LFTag"]
        return ("lf_tag", None, None, None, None, f"{g.get('TagKey', '')}={g.get('TagValues')}")
    if "LFTagExpression" in r:
        return ("lf_tag_expression", None, None, None, None, str(r["LFTagExpression"].get("Name", "")))
    return ("other", None, None, None, None, ",".join(sorted(r)))


UNRESOLVED_KINDS = {"lf_tag_policy", "lf_tag", "lf_tag_expression", "other"}


def _s3_prefix(arn):
    """arn:aws:s3:::bucket/prefix -> s3://bucket/prefix (no trailing slash)."""
    a = str(arn or "")
    return ("s3://" + a[len("arn:aws:s3:::"):]).rstrip("/") if a.startswith("arn:aws:s3:::") else a.rstrip("/")


def _under(location, prefix):
    loc = str(location or "").rstrip("/")
    return bool(prefix) and (loc == prefix or loc.startswith(prefix + "/"))


def evaluate(role, tables, confidence, unknowns, finding):
    findings = []
    perms, allp, settings = tables.get("permissions"), tables.get("all_permissions"), tables.get("settings")
    filters, glue, resources, iamp = tables.get("data_cells_filters"), tables.get("tables"), tables.get("resources"), tables.get("iam_policies")
    opt_ins, trails = tables.get("opt_ins"), tables.get("cloudtrail")
    role_cf = (role or "").strip()
    kind = _kind(role_cf)

    def entries(blob):
        if isinstance(blob, dict) and isinstance(blob.get("PrincipalResourcePermissions"), list):
            return [e for e in blob["PrincipalResourcePermissions"] if isinstance(e, dict)]
        return None

    mine = entries(perms) if perms is not None else None
    everyone = entries(allp) if allp is not None else None
    if perms is not None and mine is None:
        unknowns.append({"check_id": "DB-06", "reason": "permissions.json has no PrincipalResourcePermissions list.", "action": f"Re-capture: {JSON_INPUTS['permissions']}"}); mine = None
    if allp is not None and everyone is None:
        unknowns.append({"check_id": "DB-06", "reason": "all_permissions.json has no PrincipalResourcePermissions list.", "action": f"Re-capture: {JSON_INPUTS['all_permissions']}"}); everyone = None
    # rows that reach everyone: IAMAllowedPrincipals (IAM alone governs) and ALLIAMPrincipals
    broad = []
    if everyone is not None:
        for e in everyone:
            pid = str((e.get("Principal") or {}).get("DataLakePrincipalIdentifier", ""))
            if pid.upper() in ("IAM_ALLOWED_PRINCIPALS", "IAMALLOWEDPRINCIPALS") or pid.upper().endswith(":IAMPRINCIPALS"):
                broad.append((pid, e))
    # glue tables -> columns (names + types) for PII and for the wildcard/exclusion maths
    columns, locations = {}, {}
    if isinstance(glue, dict) and isinstance(glue.get("TableList"), list):
        for t in glue["TableList"]:
            if isinstance(t, dict):
                cols = [(c.get("Name"), c.get("Type")) for c in ((t.get("StorageDescriptor") or {}).get("Columns") or []) if isinstance(c, dict)]
                cols += [(c.get("Name"), c.get("Type")) for c in (t.get("PartitionKeys") or []) if isinstance(c, dict)]
                columns[(t.get("DatabaseName"), t.get("Name"))] = cols
                locations[(t.get("DatabaseName"), t.get("Name"))] = str((t.get("StorageDescriptor") or {}).get("Location") or "")
    elif glue is not None:
        unknowns.append({"check_id": "DB-06", "reason": "tables.json has no TableList (aws glue get-tables output); PII columns and column-filter maths were not assessed.", "action": f"Re-capture: {JSON_INPUTS['tables']}"})
        glue = None

    cells, cells_ok = [], False
    if isinstance(filters, dict) and isinstance(filters.get("DataCellsFilters"), list):
        cells = [f for f in filters["DataCellsFilters"] if isinstance(f, dict)]
        cells_ok = True
    elif filters is not None:
        unknowns.append({"check_id": "DB-06", "reason": "data_cells_filters.json has no DataCellsFilters list; granted filters could not be resolved to columns.", "action": f"Re-capture: {JSON_INPUTS['data_cells_filters']}"})
    cell_defs = {(f.get("DatabaseName"), f.get("TableName"), f.get("Name")): f for f in cells}
    unresolved_filters = []

    def readable_columns(entry):
        """Columns the entry lets its principal read on a table: all, an inclusion list, all minus exclusions, or a granted cells filter's columns."""
        k, db, tbl, inc, exc, extra = _res(entry.get("Resource"))
        perms_ = set(entry.get("Permissions") or [])
        if not perms_ & READ:
            return {}
        out = {}
        if k == "catalog":
            # ALL / SUPER_USER on the catalog reaches every table in every database
            for (d, t), cols in columns.items():
                out[(d, t)] = set(c for c, _ in cols) or {"*"}
            if not columns:
                out[("*", "*")] = {"*"}
        elif k == "data_cells_filter":
            if "SELECT" not in perms_:
                return {}
            f = cell_defs.get((db, tbl, extra))
            if f is None:
                unresolved_filters.append(f"{extra} on {db}.{tbl}")
                return {}
            allcols = [c for c, _ in columns.get((db, tbl), [])]
            finc = list(f.get("ColumnNames") or [])
            fexc = list((f.get("ColumnWildcard") or {}).get("ExcludedColumnNames") or [])
            if finc:
                out[(db, tbl)] = set(finc)
            elif fexc:
                out[(db, tbl)] = set(allcols) - set(fexc) if allcols else {"*"}
            else:
                out[(db, tbl)] = set(allcols) if allcols else {"*"}
        elif k == "table":
            allcols = [c for c, _ in columns.get((db, tbl), [])]
            if inc is not None and inc:
                out[(db, tbl)] = set(inc)
            elif exc:
                out[(db, tbl)] = set(allcols) - set(exc) if allcols else {"*"}
            else:
                out[(db, tbl)] = set(allcols) if allcols else {"*"}
        elif k == "all_tables":
            for (d, t), cols in columns.items():
                if d == db:
                    out[(d, t)] = set(c for c, _ in cols) or {"*"}
            if not any(d == db for d, _ in columns):
                out[(db, "*")] = {"*"}
        elif k == "database":
            pass  # database permissions are metadata-level (DESCRIBE/CREATE_TABLE), not data reads
        return out

    def label(entry, via="direct", only=None):
        k, db, tbl, inc, exc, extra = _res(entry.get("Resource"))
        where = {"table": f"{db}.{tbl}", "all_tables": f"{db}.* (TableWildcard)", "database": f"database {db}", "catalog": "catalog",
                 "data_location": f"data location {extra}", "lf_tag_policy": f"LF-tag policy {extra}", "lf_tag": f"LF-tag {extra}",
                 "lf_tag_expression": f"LF-tag expression {extra}", "data_cells_filter": f"cells filter {extra} on {db}.{tbl}"}.get(k, k)
        cols = f" columns={inc}" if inc else (f" excluding={exc}" if exc else "")
        perms_ = sorted(set(entry.get("Permissions") or []) & only) if only else sorted(entry.get("Permissions") or [])
        return f"{where}:{'/'.join(perms_)}{cols} ({via})"

    # ---- unresolved grant forms (LF-TBAC, tag expressions, conditional grants) -> DB-06, never assumed harmless ----
    unresolved = []
    for via, e in [("direct", e) for e in (mine or [])] + [("via " + pid, e) for pid, e in broad]:
        k = _res(e.get("Resource"))[0]
        if k in UNRESOLVED_KINDS or e.get("Condition"):
            unresolved.append(label(e, via) + (" [Condition]" if e.get("Condition") else ""))
    if unresolved:
        unknowns.append({"check_id": "DB-06", "reason": f"grant form(s) this module does not resolve: {', '.join(sorted(unresolved))}. LF-tag-based access is the union with named-resource grants; the tables they reach were NOT added to DB-02/03/08.",
                         "action": "aws lakeformation get-resource-lf-tags per table (or list-permissions --resource per table for effective permissions) and judge those tables by hand."})

    # ---- DB-01 ----
    if mine is not None:
        writes = [label(e, only=WRITE) for e in mine if set(e.get("Permissions") or []) & WRITE and _res(e.get("Resource"))[0] in ("table", "all_tables", "database", "catalog", "lf_tag_policy", "lf_tag_expression")]
        writes += [label(e, "via " + pid, only=WRITE) for pid, e in broad if set(e.get("Permissions") or []) & WRITE]
        grantable = [label(e) for e in mine if e.get("PermissionsWithGrantOption")]
        if writes or grantable:
            findings.append(finding(
                "DB-01", f"AI principal '{role}' holds write or grant authority in Lake Formation",
                "CRITICAL", confidence, role,
                (f"Write permissions: {', '.join(sorted(writes))}. " if writes else "") + (f"Grantable permissions (can re-grant to others): {', '.join(sorted(grantable))}. " if grantable else "")
                + "IAMAllowedPrincipals/ALLIAMPrincipals grants apply to every IAM principal with Glue/S3 access, including this one.",
                ["Revoke INSERT/DELETE/ALTER/DROP/ALL and every grant option from the agent's principal; revoke IAMAllowedPrincipals Super on the databases it uses."],
            ))
    # ---- DB-02 / DB-03 / DB-08 ----
    readable = {}
    if mine is not None:
        for e in mine:
            for k, v in readable_columns(e).items():
                readable.setdefault(k, set()).update(v)
        for pid, e in broad:
            for k, v in readable_columns(e).items():
                readable.setdefault(k, set()).update(v)
        if unresolved_filters:
            unknowns.append({"check_id": "DB-06", "reason": f"data cells filter(s) granted with SELECT but absent from data_cells_filters.json: {', '.join(sorted(unresolved_filters))}; their column/row scope was not assessed and the tables were not counted as protected.",
                             "action": "aws lakeformation get-data-cells-filter --table-catalog-id <acct> --database-name <db> --table-name <t> --name <filter>"})
        base = sorted(f"{d}.{t}" + (" (all columns)" if "*" in c or (columns.get((d, t)) and c >= {x for x, _ in columns[(d, t)]}) else f" ({len(c)} column(s))") for (d, t), c in readable.items())
        if any(set(e.get("Permissions") or []) & {"SUPER_USER"} for e in mine):
            base.append("SUPER_USER on the catalog (every current and future table)")
        if base:
            findings.append(finding(
                "DB-02", f"AI principal '{role}' reads Data Catalog tables directly",
                "HIGH", confidence, role,
                f"SELECT reaches: {', '.join(base)}. " + ("Some grants come through IAMAllowedPrincipals/ALLIAMPrincipals (see DB-07). " if broad else "")
                + "Lake Formation column filters narrow columns; rows are unfiltered unless a data cells filter applies.",
                ["Grant SELECT with an inclusion list (TableWithColumns) or a data cells filter; never Super or unfiltered SELECT on PII tables."],
            ))
    if glue is not None and mine is not None:
        exposed = []
        for (d, t), cols in columns.items():
            rc = readable.get((d, t)) or readable.get((d, "*"))
            if not rc:
                continue
            for c, ty in cols:
                if c and PII_TOKENS.search(c) and ("*" in rc or c in rc):
                    exposed.append((d, t, c, "Restricted" if RESTRICTED.search(c) else "Confidential"))
        for tier, sev in (("Restricted", "HIGH"), ("Confidential", "MEDIUM")):
            cols_ = sorted(f"{d}.{t}.{c}" for d, t, c, tr in exposed if tr == tier)
            if cols_:
                findings.append(finding(
                    "DB-03", f"{tier}-tier columns readable by '{role}'",
                    sev, confidence, ";".join(cols_[:3]),
                    f"PII-named columns at {tier} floor within the principal's column grants: {', '.join(cols_)} (column names from the Glue schema; no data sampled).",
                    ["Grant SELECT with ColumnWildcard.ExcludedColumnNames covering these columns, or a data cells filter; serve hashed columns through a curated table."],
                ))
        # DB-08: is any column filter / cells filter actually narrowing what it reads?
        if exposed:
            filtered_tables = set()
            for e in mine:
                k, d, t, inc, exc, _ = _res(e.get("Resource"))
                if k == "table" and (inc or exc):
                    filtered_tables.add((d, t))
            cell_tables = {(f.get("DatabaseName"), f.get("TableName")) for f in cells}
            # a filter protects a table only when granted with SELECT AND its definition was captured
            granted_filters = set()
            for e in mine:
                k, d, t, _, _, name = _res(e.get("Resource"))
                if k == "data_cells_filter" and "SELECT" in set(e.get("Permissions") or []) and (d, t, name) in cell_defs:
                    granted_filters.add((d, t))
            # a table read in full through ANOTHER grant is not protected by a filter on it
            full_read = {(d, t) for (d, t), c in readable.items() if "*" in c or (columns.get((d, t)) and c >= {x for x, _ in columns[(d, t)]})}
            unprotected = sorted({f"{d}.{t}" for d, t, _, _ in exposed if ((d, t) not in filtered_tables and (d, t) not in granted_filters) or (d, t) in full_read})
            if unprotected:
                findings.append(finding(
                    "DB-08", f"No column filter or data cells filter narrows '{role}' on PII tables",
                    "HIGH", confidence, ";".join(unprotected[:3]),
                    f"Tables read with PII columns and no column inclusion/exclusion list or granted cells filter: {', '.join(unprotected)}. "
                    + (f"Cells filters exist on {', '.join(sorted(f'{d}.{t}' for d, t in cell_tables))} but are not granted to this principal. " if cell_tables - granted_filters else "")
                    + "Lake Formation has no masking function: a column is either visible or excluded.",
                    ["Re-grant SELECT via TableWithColumns with ExcludedColumnNames, or create and grant a data cells filter (column list + row filter)."],
                ))
    # ---- DB-04 ----
    if glue is not None:
        views = [(d, t) for (d, t), _ in columns.items() if any(x in (t or "").lower() for x in ("mask", "hash", "redact", "curated", "governed", "anonym", "pseudonym"))]
        if not views and readable:
            findings.append(finding(
                "DB-04", "No curated / masked table layer detected in the Data Catalog",
                "MEDIUM", confidence, "glue tables",
                f"{len(columns)} table(s) in the captured databases; none named like a curated or masked layer, and Lake Formation offers no masking function. AI access appears to go straight at raw tables.",
                ["Materialize a curated database of hashed/omitted-column tables (Glue ETL or Athena CTAS) and grant the agent SELECT there only."],
            ))
    # ---- DB-05 / DB-09: settings + CloudTrail ----
    s = settings.get("DataLakeSettings") if isinstance(settings, dict) else None
    settings_ok = isinstance(s, dict) and all(isinstance(s.get(k, []), list) for k in ("DataLakeAdmins", "ReadOnlyAdmins", "CreateDatabaseDefaultPermissions", "CreateTableDefaultPermissions"))
    admins = []
    if settings_ok:
        admins = [a.get("DataLakePrincipalIdentifier") for a in s.get("DataLakeAdmins", []) if isinstance(a, dict)]
        ro_admins = [a.get("DataLakePrincipalIdentifier") for a in s.get("ReadOnlyAdmins", []) if isinstance(a, dict)]
        create_db_default = [p for p in s.get("CreateDatabaseDefaultPermissions", []) if isinstance(p, dict)]
        create_tbl_default = [p for p in s.get("CreateTableDefaultPermissions", []) if isinstance(p, dict)]
        iam_only_default = any(str((p.get("Principal") or {}).get("DataLakePrincipalIdentifier", "")).upper() in ("IAM_ALLOWED_PRINCIPALS", "IAMALLOWEDPRINCIPALS") for p in create_db_default + create_tbl_default)
        problems = []
        if iam_only_default:
            problems.append("default permissions grant IAMAllowedPrincipals Super on NEW databases/tables ('Use only IAM access control' is on): new PII tables are governed by IAM alone until someone revokes it")
        if role_cf in admins:
            problems.append("the principal is a Data lake administrator: every Lake Formation permission check passes")
        if problems:
            findings.append(finding(
                "DB-07", f"Lake Formation settings widen '{role}' beyond its grants",
                "CRITICAL" if role_cf in admins else "HIGH", confidence, "data lake settings",
                "; ".join(problems) + ".",
                ["Turn off 'Use only IAM access control for new databases/tables'; remove the agent from Data lake administrators; revoke IAMAllowedPrincipals on existing PII tables."],
            ))
    elif settings is not None:
        unknowns.append({"check_id": "DB-06", "reason": "settings.json has no well-formed DataLakeSettings object (admins and default-permission lists); admins, defaults and the audit-trail context were not assessed.", "action": f"Re-capture: {JSON_INPUTS['settings']}"})
    # ---- DB-05 / DB-09: CloudTrail ----
    trail_list = trails.get("trailList") if isinstance(trails, dict) else None
    if isinstance(trail_list, list) and settings_ok:
        tl = [x for x in trail_list if isinstance(x, dict)]
        multi = [x.get("Name") for x in tl if x.get("IsMultiRegionTrail")]
        validated = [x.get("Name") for x in tl if x.get("LogFileValidationEnabled")]
        if not tl:
            findings.append(finding(
                "DB-05", "No CloudTrail trail is configured: GetDataAccess events are not retained beyond Event history",
                "HIGH", confidence, "cloudtrail",
                "describe-trails returned no trails. Lake Formation credential vends (GetDataAccess) then exist only in the 90-day CloudTrail Event history, with no retention or alerting.",
                ["Create a multi-region trail to a locked S3 bucket with log file validation; alert on GetDataAccess for the agent's principal outside its curated database."],
            ))
        else:
            findings.append(finding(
                "DB-05", "Audit trail: Lake Formation credential vends are CloudTrail GetDataAccess events; trail(s) present",
                "INFO", "probable" if confidence == "confirmed" else confidence, "cloudtrail GetDataAccess",
                f"{len(tl)} trail(s) ({len(multi)} multi-region, {len(validated)} with log file validation); {len(admins)} data lake admin(s) and {len(ro_admins)} read-only admin(s) can review permissions. "
                "GetDataAccess is emitted for temporary-credential requests on REGISTERED locations only (Redshift federated catalogs do not emit it); whether the trail's event selectors keep these management events, and retention on the bucket, were not captured.",
                ["Confirm management events are logged on the trail and the bucket has retention; alert on GetDataAccess for the agent's principal outside its curated database."],
            ))
    elif trails is not None and settings_ok:
        unknowns.append({"check_id": "DB-06", "reason": "cloudtrail.json has no trailList (aws cloudtrail describe-trails output); the audit trail was not assessed.", "action": f"Re-capture: {JSON_INPUTS['cloudtrail']}"})
    else:
        unknowns.append({"check_id": "DB-06", "reason": "audit trail not assessed: cloudtrail.json was not captured" + ("" if settings_ok else " and settings.json is not well-formed") + ". Whether GetDataAccess events are retained anywhere is unknown.",
                         "action": f"Capture: {JSON_INPUTS['cloudtrail']}"})
    if settings_ok:
        findings.append(finding(
            "DB-09", "Audit trail of the AI principal has known blind spots",
            "MEDIUM", "probable" if confidence == "confirmed" else confidence, "cloudtrail",
            "Query text is not in GetDataAccess (only the table/location and columns vended); direct S3 reads that bypass Lake Formation (hybrid access mode, IAMAllowedPrincipals, or S3-level IAM grants) appear only as S3 data events, whose enablement was not captured here; Athena query history lives in Athena, Redshift Spectrum history in Redshift, and Redshift federated catalogs emit no GetDataAccess.",
            ["Enable S3 data events for the data lake buckets; correlate Athena/Redshift query history with GetDataAccess."],
        ))
    # ---- DB-ID-01 ----
    problems, sev = [], "HIGH"
    if kind == "user":
        problems.append("the principal is an IAM USER (long-lived access keys) rather than a role assumed with temporary credentials")
    elif kind in ("unknown",):
        problems.append("the principal is not an IAM role/user ARN, SAML, or Identity Center identity")
    if isinstance(iamp, dict) and isinstance(iamp.get("AttachedPolicies"), list):
        names = {str(p.get("PolicyName", "")) for p in iamp["AttachedPolicies"] if isinstance(p, dict)}
        admin = sorted(names & ADMIN_POLICIES)
        s3read = sorted(names & S3_READ_POLICIES)
        if admin:
            problems.append(f"attached AWS-managed policy(ies) {', '.join(admin)} grant administrative or full S3 access by their published documents: Lake Formation permissions are bypassed wherever a location is not registered in Lake Formation mode"); sev = "CRITICAL"
        elif s3read:
            problems.append(f"attached AWS-managed policy(ies) {', '.join(s3read)} read S3 directly by their published documents: data at unregistered or hybrid-mode locations is readable without any Lake Formation grant")
        customer = sorted(n for n in names if n not in ADMIN_POLICIES | S3_READ_POLICIES)
        unknowns.append({"check_id": "DB-06",
                         "reason": (f"attached policy(ies) {', '.join(customer)} were judged by name only; " if customer else "") + "inline policies, group memberships (IAM users), permission boundaries, SCPs and bucket policies were not captured: whether s3:GetObject on the data lake buckets is granted outside the named AWS-managed policies is unknown.",
                         "action": "aws iam get-policy-version for each attached policy; aws iam list-role-policies / list-user-policies + get-*-policy for inline ones; aws iam list-groups-for-user; aws s3api get-bucket-policy for the lake buckets."})
    elif iamp is not None:
        unknowns.append({"check_id": "DB-06", "reason": "iam_policies.json has no AttachedPolicies list; the S3-bypass question was not assessed.", "action": f"Re-capture: {JSON_INPUTS['iam_policies']}"})
    if problems:
        findings.append(finding(
            "DB-ID-01", f"AI principal '{role}' identity is wider than its Lake Formation grants",
            sev, confidence, role,
            "; ".join(problems) + ".",
            ["Run the agent as an IAM role with temporary credentials, no S3 managed policies, and only lakeformation:GetDataAccess + glue:Get* for the curated database."],
        ))
    # ---- DB-07: everyone paths + hybrid mode (judged per principal from opt-ins) ----
    hybrid, hybrid_iam_governed = [], []
    if isinstance(resources, dict) and isinstance(resources.get("ResourceInfoList"), list):
        hybrid = [r.get("ResourceArn") for r in resources["ResourceInfoList"] if isinstance(r, dict) and r.get("HybridAccessEnabled")]
        if not resources["ResourceInfoList"]:
            unknowns.append({"check_id": "DB-06", "reason": "no S3 locations are registered with Lake Formation: every table location is governed by IAM alone, and Lake Formation grants are metadata only.", "action": "Register the data lake locations in Lake Formation mode."})
    elif resources is not None:
        unknowns.append({"check_id": "DB-06", "reason": "resources.json has no ResourceInfoList.", "action": f"Re-capture: {JSON_INPUTS['resources']}"})
    if hybrid:
        prefixes = [_s3_prefix(h) for h in hybrid]
        hybrid_tables = {(d, t): loc for (d, t), loc in locations.items() if any(_under(loc, p) for p in prefixes)}
        opt_list = opt_ins.get("LakeFormationOptInsInfoList") if isinstance(opt_ins, dict) else None
        if glue is None or not locations:
            unknowns.append({"check_id": "DB-06", "reason": f"registered location(s) in hybrid access mode: {', '.join(sorted(str(h) for h in hybrid))}; without Glue table locations (tables.json) the tables under them are unknown.", "action": f"Capture: {JSON_INPUTS['tables']}"})
        elif not isinstance(opt_list, list):
            unknowns.append({"check_id": "DB-06", "reason": f"registered location(s) in hybrid access mode: {', '.join(sorted(str(h) for h in hybrid))} (tables: {', '.join(sorted(f'{d}.{t}' for d, t in hybrid_tables)) or 'none captured'}); "
                             + ("opt_ins.json was not captured" if opt_ins is None else "opt_ins.json has no LakeFormationOptInsInfoList") + ", so whether Lake Formation or IAM governs this principal there is unknown.",
                             "action": f"Capture: {JSON_INPUTS['opt_ins']}"})
        else:
            opted = set()
            for o in opt_list:
                if not isinstance(o, dict) or str((o.get("Principal") or {}).get("DataLakePrincipalIdentifier", "")) != role_cf:
                    continue
                k, d, t, _, _, _ = _res(o.get("Resource"))
                opted.add((k, d, t))
            for (d, t), loc in sorted(hybrid_tables.items(), key=lambda x: (x[0][0] or "", x[0][1] or "")):
                if ("catalog", None, None) in opted or ("database", d, None) in opted or ("table", d, t) in opted:
                    continue
                hybrid_iam_governed.append(f"{d}.{t} at {loc} (principal not opted in: IAM governs)")
    if broad or hybrid_iam_governed:
        findings.append(finding(
            "DB-07", f"Raw-to-curated boundary crossed by everyone-grants or hybrid access for '{role}'",
            "HIGH", confidence, role,
            (f"Grants to everyone: {', '.join(sorted(label(e, 'via ' + pid) for pid, e in broad))}. " if broad else "")
            + (f"Tables under registered locations in hybrid access mode where this principal is not opted in, so its IAM S3 permissions decide: {', '.join(hybrid_iam_governed)}. " if hybrid_iam_governed else "")
            + "Revoking the principal's own Lake Formation grants would not close these paths.",
            ["Revoke IAMAllowedPrincipals / ALLIAMPrincipals grants on PII databases and tables; opt the principal in (or move the location out of hybrid access mode) so Lake Formation governs it."],
        ))
    # ---- DB-10 ----
    if mine is not None:
        locs = [label(e) for e in mine if _res(e.get("Resource"))[0] == "data_location"]
        locs += [label(e, "via " + pid) for pid, e in broad if _res(e.get("Resource"))[0] == "data_location"]
        if locs:
            findings.append(finding(
                "DB-10", f"AI principal '{role}' holds data location permissions",
                "HIGH", confidence, role,
                f"DATA_LOCATION_ACCESS: {', '.join(sorted(locs))}. The principal can create Data Catalog tables pointing at these S3 prefixes (and their children), which is how data is re-registered outside the curated boundary.",
                ["Revoke DATA_LOCATION_ACCESS from the agent; only ETL roles need it."],
            ))

    plan_inputs = {
        "dialect": "lakeformation", "role": role, "principal_kind": kind,
        "raw_tables": [{"schema": d, "table": t, "columns": sorted(c) if "*" not in c else ["*"]} for (d, t), c in sorted(readable.items(), key=lambda x: (x[0][0] or "", x[0][1] or ""))],
        "pii_columns": [{"schema": d, "table": t, "column": c, "type": ty, "tier": "Restricted" if RESTRICTED.search(c) else "Confidential"}
                        for (d, t), cols in sorted(columns.items(), key=lambda x: (x[0][0] or "", x[0][1] or "")) for c, ty in cols if c and PII_TOKENS.search(c)],
        "everyone_grants": [label(e, pid) for pid, e in broad], "hybrid_locations": hybrid, "hybrid_iam_governed": hybrid_iam_governed,
        "unresolved_grants": sorted(unresolved),
        "inputs_present": {k: tables.get(k) is not None for k in JSON_INPUTS},
        "planner_supported": False, "partial_by_design": True,
    }
    return findings, plan_inputs
