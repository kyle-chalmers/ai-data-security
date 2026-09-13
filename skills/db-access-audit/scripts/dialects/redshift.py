"""Amazon Redshift — recorded psql --csv outputs (see sql/redshift/README.md).

Identity model: the AI principal is a database USER (IAM-auth users appear as IAM:<name> /
IAMA:<name>). Privileges reach it directly, through roles (svv_user_grants, then role-to-role grants
walked transitively), through groups (pg_group), and through PUBLIC. A relation grant is effective
only with USAGE on its schema (otherwise a LOW latent grant). Scoped grants (privilege_scope =
TABLES at schema or database level) cover every current and future table. Ownership is write
authority with no grant row. Column-level grants are read/write paths with no relation row.
Identifier comparison follows enable_case_sensitive_identifier for object names; identity names
are compared as recorded (a quoted username keeps its case regardless of the setting).
"""

import json

WRITE_PRIVS = {"INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER", "ALL"}
READ_PRIVS = {"SELECT", "ALL"}
BASE_TYPES = {"TABLE", "BASE TABLE", "EXTERNAL TABLE", "SHARED TABLE"}
ADMIN_ROLES = {"sys:superuser", "sys:dba", "sys:secadmin"}
IAM_WRITE = {"UNLOAD", "CREATE MODEL", "EXTERNAL FUNCTION", "EXFUNC"}
IAM_READ = {"COPY"}

PACK = {
    "grants": {"namespace_name", "relation_name", "table_type", "privilege_type", "identity_name", "identity_type"},
    "schema_grants": {"namespace_name", "privilege_type", "privilege_scope", "identity_name", "identity_type"},
    "database_grants": {"database_name", "privilege_type", "privilege_scope", "identity_name", "identity_type"},
    "column_grants": {"namespace_name", "relation_name", "column_name", "privilege_type", "identity_name", "identity_type"},
    "ownership": {"schema_name", "relation_name", "relation_type", "owner"},
    "pii_columns": {"table_schema", "table_name", "column_name", "tier_floor"},
    "masked_views": {"table_schema", "table_name", "has_masking_signal"},
    "policy_attachment": {"kind", "table_schema", "table_name", "grantee", "grantee_type", "output_columns", "policy_name"},
    "identity": {"kind", "name", "detail"},
    "external_paths": {"schema_name", "kind", "identity_name", "identity_type", "privilege_type"},
    "iam_privileges": {"iam_arn", "command_type", "identity_name", "identity_type"},
    "audit_logging": {"name", "setting"},
}
CAPTURE = "psql \"<conninfo>\" --csv -q -v ON_ERROR_STOP=1 -v ai_user='<ai-user>' -v org_restricted='(^|_)(__none__)(_|$)' -v org_confidential='(^|_)(__none__)(_|$)' -f sql/redshift/<file>.sql"
PRECONDITION = ("SVV_RELATION_PRIVILEGES shows other identities' rows only to superusers (or SYSLOG ACCESS UNRESTRICTED); "
                "SVV_*_PRIVILEGES / SVV_*_GRANTS need ACCESS SYSTEM TABLE; the masking/RLS views return zero rows to anyone "
                "but superusers and sys:secadmin. Capture as a superuser; the evaluator fails closed otherwise.")


def _truthy(v):
    return str(v).strip().lower() in ("t", "true", "1", "yes")


def _columns(raw):
    """output_columns as recorded by SVV_ATTACHED_MASKING_POLICY: a JSON-like array (["a","b"]) or
    a brace list ({a,b}). Returns the list of column identifiers; SUPER paths keep their dots."""
    text = (raw or "").strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            data = json.loads(text)
            return [str(x).strip() for x in data if str(x).strip()] if isinstance(data, list) else []
        except ValueError:
            text = text.strip("[]")
    text = text.strip("{}")
    return [c.strip().strip('"') for c in text.split(",") if c.strip().strip('"')]


def evaluate(role, tables, confidence, unknowns, finding):
    findings = []
    grants, sgrants, dgrants = tables.get("grants"), tables.get("schema_grants"), tables.get("database_grants")
    cgrants, owners, pii, views = tables.get("column_grants"), tables.get("ownership"), tables.get("pii_columns"), tables.get("masked_views")
    policies, ident, ext, iamp, audit = tables.get("policy_attachment"), tables.get("identity"), tables.get("external_paths"), tables.get("iam_privileges"), tables.get("audit_logging")

    # ---- settings that shape comparison and visibility ----
    kv = {a["name"]: a["setting"] for a in (audit or [])}
    case_sensitive = _truthy(kv.get("enable_case_sensitive_identifier", "false"))
    auditor_super = _truthy(kv.get("auditor_is_superuser", "false"))

    def obj(v):
        """Object identifier normaliser: lowercase unless the cluster preserves identifier case."""
        v = (v or "").strip()
        return v if case_sensitive else v.lower()

    def who(v):
        """Identity names are compared exactly as recorded (quoted usernames keep their case)."""
        return (v or "").strip()

    role_id = who(role)

    # ---- identity closure ----
    roles, groups, attrs, auditor = set(), set(), {}, {"user": None, "usesuper": False, "roles": set()}
    if ident is not None:
        direct = {who(r["name"]) for r in ident if r["kind"] == "user_role"}
        edges = {}
        for r in ident:
            if r["kind"] == "role_role":
                edges.setdefault(who(r["name"]), set()).add(who(r["detail"]))  # role_name holds granted_role_name
        roles = set(direct)
        frontier = list(direct)
        while frontier:
            cur = frontier.pop()
            for nxt in edges.get(cur, ()):
                if nxt not in roles:
                    roles.add(nxt)
                    frontier.append(nxt)
        groups = {who(r["name"]) for r in ident if r["kind"] == "group"}
        attrs = {r["name"]: r["detail"] for r in ident if r["kind"] == "attr"}
        for r in ident:
            if r["kind"] == "auditor":
                if r["name"] == "user":
                    auditor["user"] = r["detail"]
                elif r["name"] == "usesuper":
                    auditor["usesuper"] = _truthy(r["detail"])
                elif r["name"] == "role":
                    auditor["roles"].add(who(r["detail"]))
    auditor_super = auditor_super or auditor["usesuper"]
    auditor_secadmin = auditor_super or "sys:secadmin" in auditor["roles"]
    principal_set = {role_id} | roles | groups
    superuser = attrs.get("usesuper") == "true"
    if ident is not None and attrs.get("exists") != "true":
        unknowns.append({"check_id": "DB-06", "reason": f"identity.csv has no pg_user row for '{role}': the AI user name may be wrong (IAM users are named IAM:<name> or IAMA:<name>).",
                         "action": "Check the exact user name with ai_principals.csv and re-run."})
    grants_partial = not auditor_super
    if grants_partial and (grants is not None or cgrants is not None):
        unknowns.append({"check_id": "DB-06",
                         "reason": "the capture did not run as a superuser: SVV_RELATION_PRIVILEGES / SVV_COLUMN_PRIVILEGES show other identities' rows only to superusers (or SYSLOG ACCESS UNRESTRICTED), so grants reaching the agent through roles, groups, or PUBLIC may be missing. Grant-derived verdicts below are partial.",
                         "action": "Re-capture grants.sql, column_grants.sql, schema_grants.sql, database_grants.sql as a superuser."})

    def mine(rows):
        return [g for g in rows if who(g["identity_type"]) == "public" or who(g["identity_name"]) in principal_set]

    def via(g):
        if who(g["identity_type"]) == "public":
            return "via PUBLIC"
        if who(g["identity_name"]) == role_id:
            return "direct"
        return f"via {g['identity_type']} {g['identity_name']}"

    s_mine = mine(sgrants) if sgrants is not None else []
    d_mine = mine(dgrants) if dgrants is not None else []
    g_mine = mine(grants) if grants is not None else []
    c_mine = mine(cgrants) if cgrants is not None else []
    owned = [(o["schema_name"], o["relation_name"], o["relation_type"], o["owner"]) for o in (owners or []) if who(o["owner"]) in principal_set]

    # USAGE on a schema: direct schema grant, database-scoped SCHEMAS USAGE, superuser, or ownership of the relation
    usage_schemas = {obj(g["namespace_name"]) for g in s_mine if g["privilege_type"].upper() == "USAGE"}
    all_schemas_usable = superuser or any(g["privilege_type"].upper() == "USAGE" and g["privilege_scope"].upper() == "SCHEMAS" for g in d_mine)
    db_tables_read = [g for g in d_mine if g["privilege_scope"].upper() == "TABLES" and g["privilege_type"].upper() in READ_PRIVS]
    db_tables_write = [g for g in d_mine if g["privilege_scope"].upper() == "TABLES" and g["privilege_type"].upper() in WRITE_PRIVS]

    def usable(schema):
        if all_schemas_usable:
            return True
        if sgrants is None:
            return True  # not captured: do not invent a latent state (DB-06 already emitted)
        return obj(schema) in usage_schemas

    # ---- DB-01 ----
    if grants is not None or owners is not None or dgrants is not None or cgrants is not None:
        writes = sorted({f"{g['namespace_name']}.{g['relation_name']}:{g['privilege_type']} ({via(g)})" for g in g_mine if g["privilege_type"].upper() in WRITE_PRIVS}
                        | {f"{g['namespace_name']}.{g['relation_name']}({g['column_name']}):UPDATE ({via(g)})" for g in c_mine if g["privilege_type"].upper() == "UPDATE"})
        scoped_w = sorted({f"schema {g['namespace_name']}:{g['privilege_type']} on TABLES ({via(g)})" for g in s_mine if g["privilege_type"].upper() in WRITE_PRIVS and g["privilege_scope"].upper() == "TABLES"}
                          | {f"database {g['database_name']}:{g['privilege_type']} on TABLES ({via(g)})" for g in db_tables_write})
        owned_txt = sorted(f"{s}.{n} ({t}, owner {o})" for s, n, t, o in owned)
        if superuser:
            writes.insert(0, "SUPERUSER (every privilege on every object)")
        if writes or scoped_w or owned_txt:
            findings.append(finding(
                "DB-01", f"AI principal '{role}' holds write authority",
                "CRITICAL", confidence, role,
                (f"Write grants: {', '.join(writes)}. " if writes else "") + (f"Scoped writes: {', '.join(scoped_w)}. " if scoped_w else "")
                + (f"Owns {len(owned_txt)} relation(s): {', '.join(owned_txt)} (an owner holds every privilege with no grant row). " if owned_txt else "")
                + "An AI principal with write access can mutate or destroy data on a bad generation or injected instruction.",
                ["REVOKE INSERT, UPDATE, DELETE, DROP, TRUNCATE ... FROM the user, its roles and groups; ALTER TABLE ... OWNER TO a data-engineering role; never grant superuser to an agent.",
                 "Re-run this audit to verify only SELECT on views remains."],
            ))
    # ---- DB-02 ----
    readable_tables, readable_cols = set(), set()
    if grants is not None:
        base_rows = [g for g in g_mine if g["privilege_type"].upper() in READ_PRIVS and (g.get("table_type") or "").upper() in BASE_TYPES]
        base = sorted({f"{g['namespace_name']}.{g['relation_name']} ({via(g)})" for g in base_rows if usable(g["namespace_name"])})
        latent = sorted({f"{g['namespace_name']}.{g['relation_name']} ({via(g)}; not exploitable yet: no USAGE on schema {g['namespace_name']})" for g in base_rows if not usable(g["namespace_name"])})
        col_reads = sorted({f"{g['namespace_name']}.{g['relation_name']}({g['column_name']}) ({via(g)})" for g in c_mine if g["privilege_type"].upper() == "SELECT" and usable(g["namespace_name"])})
        scoped = sorted({f"schema {g['namespace_name']} ({via(g)})" for g in s_mine if g["privilege_type"].upper() in READ_PRIVS and g["privilege_scope"].upper() == "TABLES" and usable(g["namespace_name"])}
                        | {f"database {g['database_name']} — every table in every schema ({via(g)})" for g in db_tables_read})
        if base or scoped or latent or col_reads:
            findings.append(finding(
                "DB-02", f"AI principal '{role}' reads base tables directly" if (base or scoped or col_reads) else f"AI principal '{role}' holds latent base-table SELECT grants",
                "HIGH" if (base or scoped or col_reads) else "LOW", confidence, role,
                (f"SELECT on base tables: {', '.join(base)}. " if base else "") + (f"Column-level SELECT: {', '.join(col_reads)}. " if col_reads else "")
                + (f"Scoped SELECT on every current and future table in: {', '.join(scoped)}. " if scoped else "")
                + (f"Latent grants (one GRANT USAGE ON SCHEMA would activate them): {', '.join(latent)}. " if latent else "")
                + ("Raw tables expose every column, including sensitive ones, with no masking layer in between." if (base or scoped or col_reads) else ""),
                ["Serve a schema of masked views and grant SELECT on those views only; drop scoped TABLES grants for the agent's identities.",
                 "Revoke latent SELECT grants too: they become live the moment someone grants schema USAGE."],
            ))
        readable_tables = {(obj(g["namespace_name"]), obj(g["relation_name"])) for g in g_mine if g["privilege_type"].upper() in READ_PRIVS and usable(g["namespace_name"])}
        readable_tables |= {(obj(s), obj(n)) for s, n, _, _ in owned}
        readable_schemas = {obj(g["namespace_name"]) for g in s_mine if g["privilege_type"].upper() in READ_PRIVS and g["privilege_scope"].upper() == "TABLES" and usable(g["namespace_name"])}
        readable_cols = {(obj(g["namespace_name"]), obj(g["relation_name"]), obj(g["column_name"])) for g in c_mine if g["privilege_type"].upper() == "SELECT" and usable(g["namespace_name"])}
        whole_db = superuser or bool(db_tables_read)

        def readable(schema, table, column):
            return whole_db or obj(schema) in readable_schemas or (obj(schema), obj(table)) in readable_tables or (obj(schema), obj(table), obj(column)) in readable_cols
    else:
        readable = None

    # ---- DB-03 / DB-08 ----
    exposed = []
    if pii is not None and readable is not None:
        exposed = [p for p in pii if readable(p["table_schema"], p["table_name"], p["column_name"])]
        for tier, sev in (("Restricted", "HIGH"), ("Confidential", "MEDIUM")):
            cols = sorted(f"{p['table_schema']}.{p['table_name']}.{p['column_name']}" for p in exposed if p["tier_floor"] == tier)
            if cols:
                findings.append(finding(
                    "DB-03", f"{tier}-tier columns readable by '{role}'",
                    sev, confidence, ";".join(cols[:3]),
                    f"PII-named columns at {tier} floor readable unmasked: {', '.join(cols)} (column names only; no data sampled).",
                    ["Serve these through masked views (omit Restricted, keyed-hash Confidential) or attach dynamic data masking policies to the agent's identities (DB-08)."],
                ))
    policy_visibility_ok = policies is not None and (bool(policies) or auditor_secadmin)
    if policies is not None and exposed:
        if not policy_visibility_ok:
            unknowns.append({"check_id": "DB-06",
                             "reason": "policy_attachment.csv is empty and the capturing user is neither a superuser nor sys:secadmin: "
                                       "SVV_ATTACHED_MASKING_POLICY / SVV_RLS_ATTACHED_POLICY return zero rows to such users, so DB-08 cannot be assessed.",
                             "action": "Re-capture policy_attachment.sql as a superuser or a sys:secadmin holder."})
        else:
            covered = set()
            for m in policies:
                if m["kind"] != "masking":
                    continue
                if who(m["grantee_type"]) == "public" or who(m["grantee"]) in principal_set:
                    for col in _columns(m.get("output_columns")):
                        covered.add((obj(m["table_schema"]), obj(m["table_name"]), obj(col)))
            unprotected = sorted(f"{p['table_schema']}.{p['table_name']}.{p['column_name']}" for p in exposed
                                 if (obj(p["table_schema"]), obj(p["table_name"]), obj(p["column_name"])) not in covered)
            rls = sorted({f"{m['table_schema']}.{m['table_name']}" for m in policies if m["kind"] == "rls"})
            if unprotected:
                findings.append(finding(
                    "DB-08", f"No masking policy attached for '{role}' on PII columns it can read",
                    "HIGH", confidence, ";".join(unprotected[:3]),
                    f"{sum(1 for m in policies if m['kind'] == 'masking')} masking attachment(s) in the database; none applies to {role}, its roles/groups, or PUBLIC on the OUTPUT columns: "
                    f"{', '.join(unprotected)}. " + (f"RLS is attached on {', '.join(rls)} (rows, not columns). " if rls else "")
                    + "A masking policy attached to a different role does nothing for this principal.",
                    ["ATTACH MASKING POLICY <policy> ON <table>(<column>) TO ROLE <the agent's role> (or PUBLIC) for each PII column; verify priority."],
                ))
    # ---- DB-04 ----
    if views is not None:
        signals = [v for v in views if _truthy(v.get("has_masking_signal"))]
        masks = [m for m in (policies or []) if m["kind"] == "masking"]
        if not signals and not masks:
            if policies is None or not policy_visibility_ok:
                unknowns.append({"check_id": "DB-06",
                                 "reason": "DB-04 not assessed: no view shows a masking signal, and the masking-policy inventory is not visible to this auditor (zero rows below sys:secadmin), so the absence of a governed layer cannot be asserted.",
                                 "action": "Re-capture policy_attachment.sql as a superuser or sys:secadmin."})
            else:
                findings.append(finding(
                    "DB-04", "No masked/governed view layer detected",
                    "MEDIUM", confidence, "views",
                    f"{len(views)} view(s), none with a masking signal in its definition, and no masking policy attached anywhere. AI access appears to go straight at raw tables.",
                    ["Stand up a schema of masked views or attach DDM policies as the only surface the AI principal can read."],
                ))
    # ---- DB-05 / DB-09 ----
    if audit is not None:
        ual = str(kv.get("enable_user_activity_logging", "")).lower()
        if ual != "true":
            findings.append(finding(
                "DB-05", "No audit trail of the AI principal's query text",
                "MEDIUM", confidence, "enable_user_activity_logging",
                f"enable_user_activity_logging = {ual or 'unknown'} (false by default): the user activity log, the only exported record of query text, is off. "
                "Connection and user logs alone do not say what the agent read.",
                ["Set enable_user_activity_logging = true in the cluster's parameter group and turn on audit logging to S3 or CloudWatch."],
            ))
        problems = ["export of audit logs to S3/CloudWatch is a cluster setting invisible from SQL (check `aws redshift describe-logging-status`)",
                    "SYS_QUERY_HISTORY shows regular users only their own rows; reviewers need superuser or SYSLOG ACCESS UNRESTRICTED",
                    "query_text in SYS_QUERY_HISTORY is truncated at 4000 characters and result_cache_hit rows re-read cached results"]
        findings.append(finding(
            "DB-09", "Audit trail of the AI principal has known blind spots",
            "MEDIUM", "probable" if confidence == "confirmed" else confidence, "sys_query_history",
            "; ".join(problems) + ".",
            ["Give the reviewing role SYSLOG ACCESS UNRESTRICTED (not superuser); export logs and set a retention policy on the bucket/log group."],
        ))
    # ---- DB-ID-01 ----
    if ident is not None and attrs.get("exists") == "true":
        problems, sev = [], "HIGH"
        if superuser:
            problems.append("the user is a SUPERUSER: every privilege check is bypassed"); sev = "CRITICAL"
        if attrs.get("usecreatedb") == "true":
            problems.append("CREATEDB is set")
        if not (role_id.startswith("IAM:") or role_id.startswith("IAMA:")):
            problems.append("authenticates with a database password (no IAM: / IAMA: prefix): a long-lived shared secret rather than temporary IAM credentials")
        if roles:
            problems.append(f"holds {len(roles)} role(s) transitively: {', '.join(sorted(roles))}")
        admin = sorted(roles & ADMIN_ROLES)
        if admin:
            problems.append(f"including system-defined admin role(s) {', '.join(admin)}"); sev = "CRITICAL"
        if groups:
            problems.append(f"member of {len(groups)} group(s): {', '.join(sorted(groups))}")
        if owned:
            problems.append(f"owns {len(owned)} relation(s): {', '.join(f'{s}.{n}' for s, n, _, _ in owned[:5])}")
        if problems:
            findings.append(finding(
                "DB-ID-01", f"AI principal '{role}' identity is wider than its direct grants",
                sev, confidence, role,
                "; ".join(problems) + ". Direct grants understate what this session can do.",
                ["Run the agent as a dedicated IAM-authenticated database user (GetClusterCredentials, no AutoCreate into PUBLIC), in no group, owning nothing, holding one role with SELECT on views.",
                 "Never grant sys:* roles or superuser to an agent identity."],
            ))
    # ---- DB-07 ----
    if grants is not None and pii is not None:
        pii_tables = {(obj(p["table_schema"]), obj(p["table_name"])) for p in pii}
        indirect = sorted({f"{g['namespace_name']}.{g['relation_name']}:{g['privilege_type']} {via(g)}" for g in g_mine
                           if who(g["identity_name"]) != role_id and g["privilege_type"].upper() in READ_PRIVS | WRITE_PRIVS
                           and (obj(g["namespace_name"]), obj(g["relation_name"])) in pii_tables}
                          | {f"{g['namespace_name']}.{g['relation_name']}({g['column_name']}):{g['privilege_type']} {via(g)}" for g in c_mine
                             if who(g["identity_name"]) != role_id and (obj(g["namespace_name"]), obj(g["relation_name"])) in pii_tables}
                          | {f"schema {g['namespace_name']}:{g['privilege_type']} on TABLES {via(g)}" for g in s_mine
                             if g["privilege_type"].upper() in READ_PRIVS | WRITE_PRIVS and g["privilege_scope"].upper() == "TABLES"}
                          | {f"database {g['database_name']}:{g['privilege_type']} on TABLES {via(g)}" for g in db_tables_read + db_tables_write})
        if indirect:
            findings.append(finding(
                "DB-07", f"Raw-to-curated boundary crossed by indirect paths for '{role}'",
                "HIGH", confidence, role,
                f"Indirect paths to PII-bearing objects: {', '.join(indirect)}. Revoking the user's direct grants would not close these.",
                ["Remove the agent's user from groups and shared roles; revoke PUBLIC grants on PII tables; replace scoped TABLES grants with view grants."],
            ))
    # ---- DB-10 ----
    if ext is not None or iamp is not None:
        ext_rows = [e for e in (ext or []) if (who(e["identity_type"]) == "public" or who(e["identity_name"]) in principal_set) and e["privilege_type"].upper() == "USAGE"]
        paths = sorted({f"{e['schema_name']} ({e['kind']}):USAGE {via(e)}" for e in ext_rows})
        iam_rows = [i for i in (iamp or []) if who(i["identity_type"]) == "public" or who(i["identity_name"]) in principal_set]
        iam_w = sorted({f"{i['command_type']} with {i['iam_arn']} {via(i)}" for i in iam_rows if i["command_type"].upper() in IAM_WRITE})
        iam_r = sorted({f"{i['command_type']} with {i['iam_arn']} {via(i)}" for i in iam_rows if i["command_type"].upper() in IAM_READ})
        if paths or iam_w or iam_r:
            findings.append(finding(
                "DB-10", f"AI principal '{role}' can reach outside the local database",
                "CRITICAL" if iam_w else "HIGH", confidence, role,
                (f"IAM-role commands granted: {', '.join(iam_w)} — UNLOAD writes query results to S3 and external functions call out of the cluster. " if iam_w else "")
                + (f"COPY (load from S3) granted: {', '.join(iam_r)}. " if iam_r else "")
                + (f"External schemas usable: {', '.join(paths)} (Spectrum / federated / streaming schemas read other systems with the schema's IAM role). " if paths else "")
                + "Whether the IAM role may write a given bucket is IAM/S3 policy the database cannot see.",
                ["REVOKE UNLOAD/COPY/EXTERNAL FUNCTION ON IAM_ROLE from the agent's identities and PUBLIC; revoke USAGE on external schemas; scope the cluster's IAM roles' S3 policies."],
            ))
        if iamp is not None:
            unknowns.append({"check_id": "DB-06", "reason": "whether the granted IAM roles may actually read/write specific S3 buckets is IAM/S3 policy outside the database; SVV_IAM_PRIVILEGES shows the grant, not the bucket authorization.",
                             "action": "Review the cluster's attached IAM roles (`aws redshift describe-clusters` → IamRoles) and their S3 policies."})
    # grant-derived passes are not passes under a partial capture
    if grants_partial and (grants is not None or cgrants is not None) and not any(f["check_id"] in ("DB-01", "DB-02", "DB-03", "DB-07") for f in findings):
        unknowns.append({"check_id": "DB-06", "reason": "no grant-derived finding (DB-01/02/03/07) was produced, but the capture was not a superuser's, so this is not a clean result.",
                         "action": "Re-capture as a superuser before treating grants as clean."})

    plan_inputs = {
        "dialect": "redshift", "role": role, "roles": sorted(roles), "groups": sorted(groups), "superuser": superuser,
        "iam_auth": role_id.startswith("IAM:") or role_id.startswith("IAMA:"), "case_sensitive_identifiers": case_sensitive,
        "raw_tables": [{"schema": s, "table": t} for s, t in sorted(readable_tables)],
        "owned": [{"schema": s, "table": n, "type": t} for s, n, t, _ in owned],
        "pii_columns": [{"schema": p["table_schema"], "table": p["table_name"], "column": p["column_name"], "type": p.get("data_type"), "tier": p["tier_floor"]} for p in (pii or [])],
        "write_grants": [{"object": f"{g['namespace_name']}.{g['relation_name']}", "privilege": g["privilege_type"], "grantee": g["identity_name"]} for g in g_mine if g["privilege_type"].upper() in WRITE_PRIVS],
        "external_objects": [{"kind": e["kind"], "name": e["schema_name"], "privilege": e["privilege_type"], "grantee": e["identity_name"]} for e in (ext or []) if e["privilege_type"] and (who(e["identity_type"]) == "public" or who(e["identity_name"]) in principal_set)],
        "iam_privileges": [{"command": i["command_type"], "iam_role": i["iam_arn"], "grantee": i["identity_name"]} for i in (iamp or []) if who(i["identity_type"]) == "public" or who(i["identity_name"]) in principal_set],
        "auditor": {"user": auditor["user"], "superuser": auditor_super, "secadmin": auditor_secadmin, "grants_partial": grants_partial},
        "inputs_present": {k: tables.get(k) is not None for k in PACK},
        "planner_supported": False,
    }
    return findings, plan_inputs
