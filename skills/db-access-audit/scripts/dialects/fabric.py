"""Microsoft Fabric Warehouse / SQL analytics endpoint — recorded sqlcmd CSVs (see sql/fabric/README.md).

Identity model: the AI principal is a database principal (Entra user or service principal, type E;
Entra group, type X). Authority reaches it through explicit GRANT/DENY rows (database, schema,
object, column), through database roles walked transitively (custom roles' permissions and the
FIXED roles db_owner / db_datareader / db_datawriter / db_ddladmin, which have no permission rows),
through ownership of schemas and objects (CONTROL with no permission row), and through the public
role. Effective SELECT on a column follows the Database Engine rules: DENY at a covering scope
beats GRANT, except that a COLUMN-level GRANT overrides an OBJECT-level DENY; CONTROL at a covering
scope implies SELECT, ALTER does not. A dynamic data mask binds only principals without UNMASK on
the column or CONTROL at a covering scope. The workspace roles Admin / Member / Contributor (CONTROL)
and Viewer (ReadData on every table), item permissions, and — for a lakehouse SQL analytics endpoint
in OneLake user-identity mode — OneLake security roles grant access outside T-SQL and are NOT
visible from it: every verdict says so, and user-identity mode makes table-access verdicts UNKNOWN.
"""

READ_IMPLYING = {"SELECT", "CONTROL"}
WRITE_PERMS = {"INSERT", "UPDATE", "DELETE", "ALTER", "CONTROL", "TAKE OWNERSHIP"}
FIXED_READ = {"db_owner", "db_datareader"}
FIXED_WRITE = {"db_owner", "db_datawriter", "db_ddladmin"}
FIXED_ADMIN = {"db_owner", "db_securityadmin", "db_accessadmin"}
DENY_READ = {"db_denydatareader"}
SELECT_COVERAGE = {"BATCH_COMPLETED_GROUP", "SCHEMA_OBJECT_ACCESS_GROUP", "SELECT"}

PACK = {
    "principals": {"name", "principal_id", "type", "type_desc", "authentication_type_desc", "is_fixed_role"},
    "role_members": {"role_name", "member_name", "member_type"},
    "grants": {"class_desc", "schema_name", "object_name", "object_type", "column_name", "permission_name", "state_desc", "grantee_name", "grantee_type"},
    "ownership": {"kind", "schema_name", "object_name", "object_type", "owner_name"},
    "modules": {"schema_name", "module_name", "module_type", "definition_visible"},
    "pii_columns": {"schema_name", "table_name", "column_name", "tier_floor", "is_masked", "masking_function"},
    "masked_views": {"kind", "schema_name", "object_name", "detail", "has_masking_signal"},
    "audit_logging": {"name", "setting"},
}
JSON_INPUTS = {"audit_status": "GET https://api.fabric.microsoft.com/v1/workspaces/<workspaceId>/warehouses/<warehouseId>/settings/sqlAudit (bearer token; Audit permission)",
               "endpoint_mode": "{\"itemType\": \"Warehouse\"} or {\"itemType\": \"SQLEndpoint\", \"accessMode\": \"delegated\"|\"userIdentity\"} from the Fabric portal / REST"}
OPTIONAL_JSON_INPUTS = {"audit_status", "endpoint_mode"}
CAPTURE = "sqlcmd -S <endpoint> -d <warehouse> -G -i sql/fabric/<file>.sql -s \",\" -W -h -1 -f 65001 -o <tmp>/<file>.csv"
PRECONDITION = ("SQL permissions are half the model: workspace roles (Admin/Member/Contributor = CONTROL; Viewer = ReadData on every table), "
                "item permissions (Read, ReadData, ReadAll), and OneLake security (user-identity mode) grant data access outside T-SQL and are "
                "not visible from the connection; sys.database_permissions shows other principals' rows only with VIEW DEFINITION / ALTER ANY USER. "
                "Capture as a workspace Admin or Member.")


def _cf(v):
    return (v or "").strip().strip('"').casefold()


def _truthy(v):
    return str(v).strip().lower() in ("1", "t", "true", "yes")


def evaluate(role, tables, confidence, unknowns, finding):
    findings = []
    principals, members, grants = tables.get("principals"), tables.get("role_members"), tables.get("grants")
    owners, modules = tables.get("ownership"), tables.get("modules")
    pii, views, audit = tables.get("pii_columns"), tables.get("masked_views"), tables.get("audit_logging")
    audit_status, endpoint = tables.get("audit_status"), tables.get("endpoint_mode")
    role_cf = _cf(role)

    # ---- endpoint mode: user-identity mode means SQL grants are not the boundary at all ----
    mode = None
    if isinstance(endpoint, dict):
        item = str(endpoint.get("itemType", "")).lower()
        mode = "warehouse" if item == "warehouse" else str(endpoint.get("accessMode", "")).lower() or None
    elif endpoint is not None:
        unknowns.append({"check_id": "DB-06", "reason": "endpoint_mode.json is not an object with itemType / accessMode; the item's access model is unknown.", "action": f"Re-capture: {JSON_INPUTS['endpoint_mode']}"})
    sql_governs = mode in ("warehouse", "delegated")
    if mode is None:
        unknowns.append({"check_id": "DB-06", "reason": "the item type / SQL analytics endpoint access mode was not captured: if this is a lakehouse SQL analytics endpoint in OneLake user-identity mode, table SQL grants are ignored and OneLake security roles govern; the table-access verdicts below assume SQL governs.",
                         "action": f"Capture: {JSON_INPUTS['endpoint_mode']}"})
    elif mode == "useridentity":
        unknowns.append({"check_id": "DB-06", "reason": "SQL analytics endpoint in OneLake user-identity mode: table SQL grants are ignored and OneLake security roles / RLS / CLS govern access, which this pack does not capture; DB-01..DB-08 table-access verdicts are UNKNOWN.",
                         "action": "Audit the OneLake security roles of the lakehouse (portal / OneLake security API) for the agent's identity."})

    # ---- identity ----
    ptype, auth = None, None
    if principals is not None:
        for p in principals:
            if _cf(p["name"]) == role_cf:
                ptype, auth = (p.get("type") or "").upper(), (p.get("authentication_type_desc") or "").upper()
        if ptype is None:
            unknowns.append({"check_id": "DB-06", "reason": f"principals.csv has no database principal named '{role}': the name may be wrong, or the principal has never been granted anything in SQL (it may still read everything through a workspace role or item permission).",
                             "action": "Check the spelling against principals.csv and the workspace role assignments in the Fabric portal."})
    roles = set()
    if members is not None:
        edges = {}
        for m in members:
            edges.setdefault(_cf(m["member_name"]), set()).add(_cf(m["role_name"]))
        frontier = [role_cf]
        while frontier:
            cur = frontier.pop()
            for r in edges.get(cur, ()):
                if r not in roles:
                    roles.add(r)
                    frontier.append(r)
    principal_set = {role_cf} | roles | {"public"}
    fixed_read, fixed_write, fixed_admin = roles & FIXED_READ, roles & FIXED_WRITE, roles & FIXED_ADMIN
    denied_all = bool(roles & DENY_READ)
    owned_schemas = {_cf(o["schema_name"]) for o in (owners or []) if o["kind"] == "schema" and _cf(o["owner_name"]) in principal_set - {"public"}}
    owned_objects = {(_cf(o["schema_name"]), _cf(o["object_name"])) for o in (owners or []) if o["kind"] == "object" and _cf(o["owner_name"]) in principal_set - {"public"}}
    unknowns.append({"check_id": "DB-06",
                     "reason": "workspace roles (Admin / Member / Contributor = CONTROL: read and write everything, unmasked; Viewer = ReadData: reads every table and view) and item permissions (Read / ReadData / ReadAll) are not visible from T-SQL; every verdict below covers SQL GRANT/DENY, roles, and ownership only, which bind the principal only if it holds item Read WITHOUT ReadData and no workspace role.",
                     "action": "Check the workspace role and item permissions of the AI principal in the Fabric portal or via the Fabric REST API; give an agent item Read only, then GRANT SELECT on curated views."})

    def mine(rows):
        return [g for g in rows if _cf(g["grantee_name"]) in principal_set]

    def via(g):
        if _cf(g["grantee_name"]) == role_cf:
            return "direct"
        if _cf(g["grantee_name"]) == "public":
            return "via public"
        return f"via role {g['grantee_name'].strip().strip(chr(34))}"

    g_mine = mine(grants) if grants is not None else []
    grant_rows = [g for g in g_mine if g["state_desc"].upper() in ("GRANT", "GRANT_WITH_GRANT_OPTION")]
    deny_rows = [g for g in g_mine if g["state_desc"].upper() == "DENY"]

    def rows_at(rows, perms, cls, schema=None, table=None, column=None):
        out = []
        for g in rows:
            if g["permission_name"].upper() not in perms or g["class_desc"] != cls:
                continue
            if cls == "SCHEMA" and _cf(g["schema_name"]) != _cf(schema):
                continue
            if cls == "OBJECT_OR_COLUMN":
                if _cf(g["schema_name"]) != _cf(schema) or _cf(g["object_name"]) != _cf(table):
                    continue
                if column is None and g["column_name"]:
                    continue
                if column is not None and _cf(g["column_name"]) != _cf(column):
                    continue
            out.append(g)
        return out

    def effective_select(schema, table, column):
        """Database Engine rules: a column-level GRANT overrides an object-level DENY; otherwise a
        DENY of SELECT/CONTROL at any covering scope wins; CONTROL at a covering scope or ownership
        implies SELECT; fixed roles db_owner/db_datareader read everything, db_denydatareader denies."""
        if denied_all:
            return False, "db_denydatareader"
        if rows_at(deny_rows, READ_IMPLYING, "OBJECT_OR_COLUMN", schema, table, column):
            return False, "column DENY"
        if rows_at(grant_rows, {"SELECT"}, "OBJECT_OR_COLUMN", schema, table, column):
            return True, "column GRANT (overrides an object-level DENY)"
        if rows_at(deny_rows, READ_IMPLYING, "OBJECT_OR_COLUMN", schema, table) or rows_at(deny_rows, READ_IMPLYING, "SCHEMA", schema) or rows_at(deny_rows, READ_IMPLYING, "DATABASE"):
            return False, "object/schema/database DENY"
        if fixed_read or (schema and _cf(schema) in owned_schemas) or (_cf(schema), _cf(table)) in owned_objects:
            return True, "fixed role or ownership"
        if rows_at(grant_rows, READ_IMPLYING, "OBJECT_OR_COLUMN", schema, table) or rows_at(grant_rows, READ_IMPLYING, "SCHEMA", schema) or rows_at(grant_rows, READ_IMPLYING, "DATABASE"):
            return True, "GRANT"
        return False, "no grant"

    def unmask_effective(schema, table, column):
        """Mask does NOT bind when the principal holds UNMASK on the column/object/schema/database, CONTROL at a covering scope, ownership, or db_owner."""
        if "db_owner" in roles or (schema and _cf(schema) in owned_schemas) or (_cf(schema), _cf(table)) in owned_objects:
            return True
        for cls, kw in (("OBJECT_OR_COLUMN", {"schema": schema, "table": table, "column": column}), ("OBJECT_OR_COLUMN", {"schema": schema, "table": table}),
                        ("SCHEMA", {"schema": schema}), ("DATABASE", {})):
            if rows_at(grant_rows, {"UNMASK", "CONTROL"}, cls, **kw):
                return True
        return False

    # ---- DB-01 ----
    if sql_governs is not False and (grants is not None or members is not None or owners is not None):
        writes = sorted({f"{g['class_desc'].lower()} {'.'.join(x for x in (g['schema_name'], g['object_name']) if x) or 'database'}"
                         f"{'(' + g['column_name'] + ')' if g['column_name'] else ''}:{g['permission_name']} ({via(g)})"
                         for g in grant_rows if g["permission_name"].upper() in WRITE_PERMS})
        if fixed_write:
            writes.insert(0, f"fixed role(s) {', '.join(sorted(fixed_write))} (write everything; no permission row)")
        owned_txt = sorted([f"schema {s}" for s in owned_schemas] + [f"{s}.{n}" for s, n in owned_objects])
        if owned_txt:
            writes.append(f"owns {', '.join(owned_txt)} (an owner holds CONTROL with no permission row)")
        if writes:
            findings.append(finding(
                "DB-01", f"AI principal '{role}' holds write authority",
                "CRITICAL", confidence, role,
                f"Write authority: {', '.join(writes)}. An AI principal with write access can mutate or destroy data on a bad generation or injected instruction. "
                "A workspace role of Contributor or above would add full write access invisibly.",
                ["REVOKE INSERT/UPDATE/DELETE/ALTER/CONTROL from the principal and its roles; remove it from db_owner/db_datawriter/db_ddladmin; transfer ownership (ALTER AUTHORIZATION) to dbo; give it item Read only."],
            ))
    # ---- DB-02 ----
    readable_tables = set()
    exec_modules = []
    if sql_governs is not False and grants is not None:
        broad = sorted({f"schema {g['schema_name']} ({via(g)})" for g in grant_rows if g["class_desc"] == "SCHEMA" and g["permission_name"].upper() in READ_IMPLYING}
                       | {f"database ({via(g)}, {g['permission_name']})" for g in grant_rows if g["class_desc"] == "DATABASE" and g["permission_name"].upper() in READ_IMPLYING})
        if fixed_read:
            broad.insert(0, f"fixed role(s) {', '.join(sorted(fixed_read))}: every table and view, present and future")
        if owned_schemas:
            broad.append(f"owned schema(s) {', '.join(sorted(owned_schemas))} (CONTROL)")
        base = sorted({f"{g['schema_name']}.{g['object_name']} ({via(g)})" for g in grant_rows if g["class_desc"] == "OBJECT_OR_COLUMN" and g["permission_name"].upper() in READ_IMPLYING and not g["column_name"] and (g.get("object_type") or "").upper() not in ("VIEW", "SQL_STORED_PROCEDURE", "SQL_SCALAR_FUNCTION", "SQL_INLINE_TABLE_VALUED_FUNCTION", "SQL_TABLE_VALUED_FUNCTION")}
                      | {f"{s}.{n} (owner)" for s, n in owned_objects})
        col_grants = sorted({f"{g['schema_name']}.{g['object_name']}({g['column_name']}) ({via(g)})" for g in grant_rows if g["class_desc"] == "OBJECT_OR_COLUMN" and g["permission_name"].upper() == "SELECT" and g["column_name"]})
        exec_modules = sorted({f"{g['schema_name']}.{g['object_name']} ({via(g)})" for g in grant_rows if g["permission_name"].upper() == "EXECUTE" and g["class_desc"] == "OBJECT_OR_COLUMN"})
        if base or broad or col_grants:
            findings.append(finding(
                "DB-02", f"AI principal '{role}' reads base tables directly",
                "HIGH", confidence, role,
                (f"SELECT on base tables: {', '.join(base)}. " if base else "") + (f"Broad read paths: {', '.join(broad)}. " if broad else "")
                + (f"Column-level SELECT: {', '.join(col_grants)} (a column GRANT overrides an object-level DENY). " if col_grants else "")
                + ("Some DENYs narrow this (see DB-03/DB-08). " if deny_rows else "")
                + "Raw tables expose every column with no masking layer in between.",
                ["Grant SELECT on a curated schema of views only; remove db_datareader and schema/database-level SELECT; revoke stray column grants."],
            ))
        if exec_modules:
            unknowns.append({"check_id": "DB-06", "reason": f"EXECUTE on module(s) {', '.join(exec_modules)}: a procedure or function returns whatever its definition selects, regardless of the caller's table grants; module bodies were not evaluated, so this is an opaque read path.",
                             "action": "Read each module's definition (sys.sql_modules) for PII table references, or revoke EXECUTE from the agent's principal and roles."})
    # ---- DB-03 / DB-08 (DDM) ----
    if sql_governs is not False and pii is not None and grants is not None:
        decided = [(p, *effective_select(p["schema_name"], p["table_name"], p["column_name"])) for p in pii]
        exposed = [p for p, ok, _ in decided if ok]
        denied_cols = sorted(f"{p['schema_name']}.{p['table_name']}.{p['column_name']}" for p, ok, why in decided if not ok and "DENY" in why)
        col_over_deny = sorted(f"{p['schema_name']}.{p['table_name']}.{p['column_name']}" for p, ok, why in decided if ok and "overrides" in why)
        for tier, sev in (("Restricted", "HIGH"), ("Confidential", "MEDIUM")):
            cols = []
            for p in exposed:
                if p["tier_floor"] != tier:
                    continue
                tag = ""
                if _truthy(p.get("is_masked")):
                    tag = " [DDM: " + (p.get("masking_function") or "?") + (", NOT binding: UNMASK/CONTROL held]" if unmask_effective(p["schema_name"], p["table_name"], p["column_name"]) else "]")
                cols.append(f"{p['schema_name']}.{p['table_name']}.{p['column_name']}{tag}")
            cols.sort()
            if cols:
                findings.append(finding(
                    "DB-03", f"{tier}-tier columns readable by '{role}'",
                    sev, confidence, ";".join(c.split(" [")[0] for c in cols[:3]),
                    f"PII-named columns at {tier} floor readable: {', '.join(cols)} (column names only; no data sampled). "
                    + (f"DENYs exclude: {', '.join(denied_cols)}. " if denied_cols else "")
                    + (f"Column GRANTs override object DENYs on: {', '.join(col_over_deny)}. " if col_over_deny else "")
                    + "A dynamic data mask shows masked values only to principals without UNMASK/CONTROL and outside Admin/Member/Contributor; it does not stop inference by range queries.",
                    ["DENY SELECT on Restricted columns; serve Confidential columns through views that hash them; keep the principal out of Contributor+ workspace roles."],
                ))
        unmasked = sorted(f"{p['schema_name']}.{p['table_name']}.{p['column_name']}" for p in exposed if not _truthy(p.get("is_masked")))
        masked_ok = sorted(f"{p['schema_name']}.{p['table_name']}.{p['column_name']}" for p in exposed if _truthy(p.get("is_masked")) and not unmask_effective(p["schema_name"], p["table_name"], p["column_name"]))
        masked_bypassed = sorted(f"{p['schema_name']}.{p['table_name']}.{p['column_name']}" for p in exposed if _truthy(p.get("is_masked")) and unmask_effective(p["schema_name"], p["table_name"], p["column_name"]))
        if unmasked or masked_bypassed:
            findings.append(finding(
                "DB-08", f"No effective masking or DENY on PII columns readable by '{role}'",
                "HIGH", confidence, ";".join((unmasked + masked_bypassed)[:3]),
                (f"{len(masked_ok)} readable PII column(s) carry a dynamic data mask that binds this principal" + (f" ({', '.join(masked_ok)})" if masked_ok else "") + ". ")
                + (f"Masked but NOT binding because the principal holds UNMASK or CONTROL (or ownership): {', '.join(masked_bypassed)}. " if masked_bypassed else "")
                + (f"No mask at all: {', '.join(unmasked)}. " if unmasked else "")
                + "A mask never binds workspace Admin/Member/Contributor.",
                ["ALTER TABLE ... ALTER COLUMN ... ADD MASKED WITH (FUNCTION = ...) and REVOKE UNMASK/CONTROL from the agent's principal and roles, or DENY SELECT on the column; verify the principal is not Contributor or above."],
            ))
    # ---- DB-04 ----
    if sql_governs is not False and views is not None:
        view_rows = [v for v in views if v["kind"] == "view"]
        signals = [v for v in view_rows if _truthy(v.get("has_masking_signal"))]
        masks = [p for p in (pii or []) if _truthy(p.get("is_masked"))]
        rls = [v for v in views if v["kind"] == "rls_policy"]
        if not signals and not masks:
            findings.append(finding(
                "DB-04", "No masked/governed view layer detected",
                "MEDIUM", confidence, "views",
                f"{len(view_rows)} view(s), none with a masking signal in its definition, and no dynamic data mask on any PII column. "
                + (f"RLS policies exist on {', '.join(sorted({v['schema_name'] + '.' + v['object_name'] for v in rls}))} (rows, not columns). " if rls else "")
                + "AI access appears to go straight at raw tables.",
                ["Stand up a schema of masked views or add dynamic data masks as the only surface the AI principal can read."],
            ))
    # ---- DB-05 / DB-09 ----
    if audit is not None:
        kv = {a["name"]: a["setting"] for a in audit}
        state, groups_, retention, predicate = None, [], None, ""
        if isinstance(audit_status, dict):
            raw_state = str(audit_status.get("state", "")).upper()
            if raw_state in ("ENABLED", "DISABLED"):
                state = raw_state
                groups_ = [str(g).upper() for g in (audit_status.get("auditActionsAndGroups") or []) if isinstance(g, str)]
                retention = audit_status.get("retentionDays")
                predicate = str(audit_status.get("predicateExpression") or "").strip()
            else:
                unknowns.append({"check_id": "DB-06", "reason": f"audit_status.json has state {raw_state or '(missing)'!r}, not Enabled/Disabled; SQL audit log state unknown.", "action": f"Re-capture: {JSON_INPUTS['audit_status']}"})
        elif audit_status is not None:
            unknowns.append({"check_id": "DB-06", "reason": "audit_status.json is not the sqlAudit settings object; SQL audit log state unknown.", "action": f"Re-capture: {JSON_INPUTS['audit_status']}"})
        else:
            unknowns.append({"check_id": "DB-06", "reason": "SQL audit log state was not captured (Fabric REST settings/sqlAudit); whether SELECTs by the agent are audited and for how long is unknown.",
                             "action": f"Capture: {JSON_INPUTS['audit_status']}"})
        covers_select = any(any(k in g for k in SELECT_COVERAGE) for g in groups_)
        if state == "DISABLED":
            findings.append(finding(
                "DB-05", "SQL audit logs are disabled for this warehouse",
                "MEDIUM", confidence, "settings/sqlAudit",
                f"SQL audit logging is DISABLED; only Query Insights (30 days, {kv.get('principal_statements_30d', '?')} statement(s) by the principal) records what the agent ran, and full text there is visible to Admin/Member/Contributor only.",
                ["Enable SQL audit logs on the warehouse with BATCH_COMPLETED_GROUP (or SCHEMA_OBJECT_ACCESS_GROUP) and a retention that fits your policy; logs land in OneLake as .xel and are read with sys.fn_get_audit_file_v2."],
            ))
        elif state == "ENABLED" and predicate:
            unknowns.append({"check_id": "DB-06", "reason": f"SQL audit logs are enabled but a predicate expression filters events ({predicate[:80]!r}); whether the agent's statements are excluded was not evaluated, so audit coverage is UNKNOWN.",
                             "action": "Review the predicate against the agent's login and statement shapes; remove exclusions that match it."})
        elif state == "ENABLED":
            findings.append(finding(
                "DB-05", "Query history and SQL audit logs — what is recorded",
                "INFO", confidence, "queryinsights.exec_requests_history",
                f"queryinsights.exec_requests_history was readable and holds {kv.get('principal_statements_30d', '?')} statement(s) by the principal out of {kv.get('total_statements_30d', '?')} in 30 days (30-day window). "
                f"SQL audit logs are ENABLED with {', '.join(groups_) or 'no action groups'}, retention {retention if retention not in (None, 0, '0') else 'unlimited'} day(s), no predicate; stored as .xel in OneLake, read with sys.fn_get_audit_file_v2. "
                "Fabric user activity is also in Microsoft Purview / admin monitoring, not in T-SQL.",
                ["Keep audit logs routed to your SIEM; make sure a reviewer holds the Audit permission."],
            ))
        problems = ["Query Insights keeps 30 days and skips system queries; full statement text is shown only to Admin/Member/Contributor"]
        if state == "ENABLED" and not covers_select:
            problems.append("SQL audit logs are enabled but no selected action or group covers SELECT statements (BATCH_COMPLETED_GROUP, SCHEMA_OBJECT_ACCESS_GROUP, or a SELECT action), so the agent's reads are not captured")
        problems.append("OneLake reads (shortcuts, Direct Lake, OneLake APIs) of the same Delta files bypass the SQL endpoint and its logs entirely")
        findings.append(finding(
            "DB-09", "Audit trail of the AI principal has known blind spots",
            "MEDIUM", "probable" if confidence == "confirmed" else confidence, "queryinsights",
            "; ".join(problems) + ".",
            ["Select BATCH_COMPLETED_GROUP in the SQL audit configuration; monitor OneLake access through Purview audit; review Query Insights per principal weekly."],
        ))
    # ---- DB-ID-01 ----
    if principals is not None and ptype is not None:
        problems, sev = [], "HIGH"
        if ptype == "E" and "@" in role:
            problems.append("the principal is an Entra USER (UPN), not a service principal: the agent shares a human's identity and audit trail")
        if ptype == "X":
            problems.append("the principal is an Entra GROUP: every member's session is 'the agent' and vice versa")
        if roles:
            problems.append(f"member of {len(roles)} database role(s): {', '.join(sorted(roles))}")
        if fixed_admin:
            problems.append(f"including fixed admin role(s) {', '.join(sorted(fixed_admin))}: it can grant itself anything"); sev = "CRITICAL"
        if owned_schemas or owned_objects:
            problems.append(f"owns {', '.join(sorted([f'schema {s}' for s in owned_schemas] + [f'{s}.{n}' for s, n in owned_objects]))} (CONTROL with no permission row)")
        if problems:
            findings.append(finding(
                "DB-ID-01", f"AI principal '{role}' identity is wider than its direct grants",
                sev, confidence, role,
                "; ".join(problems) + ". Workspace role membership (not visible here) may widen it further.",
                ["Run the agent as a dedicated Entra service principal with item Read only (no workspace role), member of no fixed role, owning nothing, with SELECT on curated views."],
            ))
    # ---- DB-07 ----
    if sql_governs is not False and grants is not None and pii is not None:
        pii_tables = {(_cf(p["schema_name"]), _cf(p["table_name"])) for p in pii}
        indirect = sorted({f"{g['class_desc'].lower()} {'.'.join(x for x in (g['schema_name'], g['object_name']) if x) or 'database'}:{g['permission_name']} {via(g)}"
                           for g in grant_rows if _cf(g["grantee_name"]) != role_cf and g["permission_name"].upper() in READ_IMPLYING | WRITE_PERMS | {"UNMASK", "EXECUTE"}
                           and (g["class_desc"] in ("DATABASE", "SCHEMA") or (_cf(g["schema_name"]), _cf(g["object_name"])) in pii_tables or g["permission_name"].upper() == "EXECUTE")})
        if fixed_read or fixed_write:
            indirect.insert(0, f"fixed role(s) {', '.join(sorted(fixed_read | fixed_write))} (no permission rows; every table)")
        if indirect:
            findings.append(finding(
                "DB-07", f"Raw-to-curated boundary crossed by indirect paths for '{role}'",
                "HIGH", confidence, role,
                f"Indirect paths to PII-bearing objects: {', '.join(indirect)}. Revoking the principal's direct grants would not close these; a Contributor+ workspace role would be another.",
                ["Remove the principal from fixed and shared roles; grant SELECT only on curated views; never rely on schema-level SELECT or role-held UNMASK for an agent."],
            ))
    # ---- DB-10 ----
    findings.append(finding(
        "DB-10", "Paths outside the warehouse are governed by OneLake and workspace settings, not T-SQL",
        "INFO", "probable" if confidence == "confirmed" else confidence, "OneLake",
        "Every warehouse table is also a Delta folder in OneLake, readable through OneLake / shortcuts / Direct Lake by anyone with item ReadAll or a Contributor+ workspace role, bypassing SQL permissions, RLS, and masking. "
        "COPY INTO / OPENROWSET reach external storage with the caller's identity or a workspace identity.",
        ["Keep the agent's OneLake access to Read (no ReadAll); enable OneLake security roles on the lakehouse/warehouse if available; never give an agent a Contributor+ workspace role."],
    ))

    plan_inputs = {
        "dialect": "fabric", "role": role, "principal_type": ptype, "authentication": auth, "roles": sorted(roles),
        "fixed_roles": sorted(fixed_read | fixed_write | fixed_admin), "owned_schemas": sorted(owned_schemas), "owned_objects": [{"schema": s, "table": n} for s, n in sorted(owned_objects)],
        "endpoint_mode": mode, "sql_governs": sql_governs,
        "pii_columns": [{"schema": p["schema_name"], "table": p["table_name"], "column": p["column_name"], "type": p.get("data_type"), "tier": p["tier_floor"], "masked": _truthy(p.get("is_masked"))} for p in (pii or [])],
        "write_grants": [{"object": ".".join(x for x in (g["schema_name"], g["object_name"]) if x), "privilege": g["permission_name"], "grantee": g["grantee_name"]} for g in grant_rows if g["permission_name"].upper() in WRITE_PERMS],
        "denies": [{"object": ".".join(x for x in (g["schema_name"], g["object_name"]) if x), "column": g["column_name"], "privilege": g["permission_name"]} for g in deny_rows],
        "execute_modules": exec_modules,
        "inputs_present": {k: tables.get(k) is not None for k in list(PACK) + list(JSON_INPUTS)},
        "planner_supported": False, "partial_by_design": True,
    }
    return findings, plan_inputs
