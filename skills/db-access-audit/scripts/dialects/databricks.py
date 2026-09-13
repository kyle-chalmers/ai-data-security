"""Databricks Unity Catalog — recorded `system.information_schema` CSVs (see sql/databricks/README.md).

Identity model: the AI principal is a service principal (applicationId UUID), a user (email), or a
group. Grants to any group in identity.csv apply to the principal; catalog- and schema-level grants
apply to every child object (INHERITED_FROM); `account users` / `users` are everyone.
"""

import re

UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
EVERYONE = {"account users", "users"}
MANAGE_PRIVS = {"MANAGE"}
VOLUME_PRIVS = {"READ VOLUME", "WRITE VOLUME"}
USE_CATALOG = {"USE CATALOG", "ALL PRIVILEGES"}
USE_SCHEMA = {"USE SCHEMA", "ALL PRIVILEGES"}
WRITE_PRIVS = {"MODIFY", "ALL PRIVILEGES", "INSERT", "UPDATE", "DELETE", "REFRESH"}
READ_PRIVS = {"SELECT", "ALL PRIVILEGES"}
BASE_TYPES = {"MANAGED", "EXTERNAL", "STREAMING_TABLE", "FOREIGN", "MANAGED_SHALLOW_CLONE", "EXTERNAL_SHALLOW_CLONE", "MATERIALIZED_VIEW"}
EXT_WRITE = {"WRITE FILES", "WRITE VOLUME", "CREATE EXTERNAL TABLE", "CREATE EXTERNAL VOLUME", "CREATE EXTERNAL LOCATION",
             "CREATE MANAGED STORAGE", "ALL PRIVILEGES", "MANAGE"}
EXT_READ = {"READ FILES", "READ VOLUME", "BROWSE"}

PACK = {
    "grants": {"level", "catalog", "schema_name", "object_name", "object_type", "owner", "grantee", "privilege_type", "inherited_from"},
    "pii_columns": {"catalog", "table_schema", "table_name", "column_name", "tier_floor"},
    "masked_views": {"catalog", "table_schema", "table_name", "definition_visible", "has_masking_signal"},
    "policy_attachment": {"kind", "catalog", "table_schema", "table_name", "column_name", "policy_name"},
    "identity": {"name"},
    "external_paths": {"kind", "name", "grantee", "privilege_type"},
    "audit_logging": {"kind", "name", "detail"},
}
CAPTURE = "dbsqlcli --table-format csv -e \"$(sed -e 's/${catalog}/<catalog>/g' -e 's/${principal}/<principal>/g' -e 's/${principal_kind}/USER|GROUP/g' sql/databricks/<file>.sql)\""
PRECONDITION = ("INFORMATION_SCHEMA shows a viewer only its own grants unless it owns the securable or is a "
                "metastore admin; capture as the catalog owner or a metastore admin.")


def _kind(principal):
    if UUID.match(principal or ""):
        return "service_principal"
    if "@" in (principal or ""):
        return "user"
    if (principal or "").lower() in EVERYONE:
        return "everyone"
    return "group"


def _cf(value):
    return (value or "").strip().casefold()


def evaluate(role, tables, confidence, unknowns, finding):
    """Identifiers are compared casefolded (INFORMATION_SCHEMA stores them lowercase); the recorded
    spelling is kept for evidence."""
    findings = []
    grants, pii, views = tables.get("grants"), tables.get("pii_columns"), tables.get("masked_views")
    policies, ident, ext, audit = tables.get("policy_attachment"), tables.get("identity"), tables.get("external_paths"), tables.get("audit_logging")
    role_cf = _cf(role)

    groups = sorted({r["name"] for r in ident if r.get("name")}) if ident is not None else []
    nested = sorted({r["name"] for r in ident if r.get("name") and str(r.get("directGroup", "")).lower() in ("false", "0", "no")}) if ident is not None else []
    principal_set = {role_cf} | {_cf(g) for g in groups} | EVERYONE
    owners_set = {role_cf} | {_cf(g) for g in groups}
    mine = [g for g in grants if _cf(g["grantee"]) in principal_set] if grants is not None else []

    def inherited(g):
        return _cf(g.get("inherited_from")) not in ("", "none")

    def via(g):
        if _cf(g["grantee"]) == role_cf:
            return "direct" if not inherited(g) else f"inherited from {g['inherited_from']}"
        if _cf(g["grantee"]) in EVERYONE:
            return f"via '{g['grantee']}' (everyone)"
        return f"via group {g['grantee']}" + ("" if not inherited(g) else f", inherited from {g['inherited_from']}")

    def obj(g):
        return ".".join(x for x in (g["schema_name"], g["object_name"]) if x) or g["catalog"]

    # effective access needs USE CATALOG and USE SCHEMA on the path (Unity Catalog privilege model)
    use_catalog = any(g["level"] == "CATALOG" and g["privilege_type"].upper() in USE_CATALOG for g in mine) \
        or any(g["level"] == "CATALOG" and _cf(g.get("owner")) in owners_set for g in mine)
    use_schemas = {_cf(g["schema_name"]) for g in mine if g["level"] == "SCHEMA" and g["privilege_type"].upper() in USE_SCHEMA} \
        | {_cf(g["schema_name"]) for g in mine if g["level"] == "SCHEMA" and _cf(g.get("owner")) in owners_set}

    def effective(schema):
        return use_catalog and (_cf(schema) in use_schemas or any(g["level"] == "CATALOG" and g["privilege_type"].upper() == "ALL PRIVILEGES" for g in mine))

    def latent_reason(schema):
        missing = [] if use_catalog else ["USE CATALOG"]
        if _cf(schema) not in use_schemas:
            missing.append(f"USE SCHEMA {schema}")
        return ", ".join(missing)

    # ---- DB-01 writes ----
    if grants is not None:
        writes = sorted({f"{g['level']} {obj(g)}:{g['privilege_type']} ({via(g)})" for g in mine if g["privilege_type"].upper() in WRITE_PRIVS})
        owned = sorted({f"{g['level']} {obj(g)} (owner {g['owner']})" for g in (grants or []) if _cf(g.get("owner")) in owners_set})
        if writes or owned:
            findings.append(finding(
                "DB-01", f"AI principal '{role}' holds write privileges",
                "CRITICAL", confidence, role,
                (f"Write grants: {', '.join(writes)}. " if writes else "") + (f"Owns {len(owned)} securable(s): {', '.join(owned)} (an owner holds every privilege on it and everything below, and can grant). " if owned else "")
                + "Catalog/schema-level and group grants apply to every current and future object.",
                ["REVOKE MODIFY (and ALL PRIVILEGES) from the principal and its groups at every level; transfer ownership to a data-engineering group.",
                 "Re-run this audit to verify only SELECT on curated views remains."],
            ))
        # ---- DB-02 base-table reads (direct table rows on non-views, plus schema/catalog SELECT) ----
        base_rows = [g for g in mine if g["level"] == "TABLE" and g["privilege_type"].upper() in READ_PRIVS and g["object_type"].upper() in BASE_TYPES]
        base = sorted({f"{obj(g)} ({via(g)})" for g in base_rows if effective(g["schema_name"])})
        latent = sorted({f"{obj(g)} ({via(g)}; not exploitable yet: missing {latent_reason(g['schema_name'])})" for g in base_rows if not effective(g["schema_name"])})
        broad = sorted({f"{g['level']} {obj(g)} ({via(g)})" for g in mine if g["level"] in ("SCHEMA", "CATALOG") and g["privilege_type"].upper() in READ_PRIVS})
        if base or broad or latent:
            findings.append(finding(
                "DB-02", f"AI principal '{role}' reads base tables directly" if (base or broad) else f"AI principal '{role}' holds latent base-table SELECT grants",
                "HIGH" if (base or broad) else "LOW", confidence, role,
                (f"SELECT on base tables: {', '.join(base)}. " if base else "") + (f"SELECT at {', '.join(broad)}: every current and future table underneath. " if broad else "")
                + (f"Latent grants (a single USE CATALOG / USE SCHEMA grant would activate them): {', '.join(latent)}. " if latent else ""),
                ["Serve the principal a curated schema of views; grant SELECT on those views only, never at catalog or schema level.",
                 "Revoke latent SELECT grants too: they become live the moment someone grants USE SCHEMA."],
            ))
        # ---- MANAGE: control-plane reach (can grant itself anything below) ----
        manage = sorted({f"{g['level']} {obj(g)} ({via(g)})" for g in mine if g["privilege_type"].upper() in MANAGE_PRIVS})
        # ---- readable PII (DB-03 / DB-08): effective paths only ----
        readable_tables = {(_cf(g["schema_name"]), _cf(g["object_name"])) for g in mine if g["level"] == "TABLE" and g["privilege_type"].upper() in READ_PRIVS and effective(g["schema_name"])}
        readable_schemas = {_cf(g["schema_name"]) for g in mine if g["level"] == "SCHEMA" and g["privilege_type"].upper() in READ_PRIVS and effective(g["schema_name"])}
        whole_catalog = use_catalog and any(g["level"] == "CATALOG" and g["privilege_type"].upper() in READ_PRIVS for g in mine)

        def readable(schema, table):
            if whole_catalog and (_cf(schema) in use_schemas or any(g["level"] == "CATALOG" and g["privilege_type"].upper() == "ALL PRIVILEGES" for g in mine)):
                return True
            return _cf(schema) in readable_schemas or (_cf(schema), _cf(table)) in readable_tables
    else:
        readable = None
        manage = []

    if pii is not None and readable is not None:
        exposed = [p for p in pii if readable(p["table_schema"], p["table_name"])]
        for tier, sev in (("Restricted", "HIGH"), ("Confidential", "MEDIUM")):
            cols = sorted(f"{p['table_schema']}.{p['table_name']}.{p['column_name']}" for p in exposed if p["tier_floor"] == tier)
            if cols:
                findings.append(finding(
                    "DB-03", f"{tier}-tier columns readable by '{role}'",
                    sev, confidence, ";".join(cols[:3]),
                    f"PII-named columns at {tier} floor readable unmasked: {', '.join(cols)} (column names only; no data sampled).",
                    ["Serve these through views that omit Restricted columns and keyed-hash Confidential ones, or attach column masks (DB-08)."],
                ))
        if policies is not None and exposed:
            masked = {(_cf(m["table_schema"]), _cf(m["table_name"]), _cf(m["column_name"])) for m in policies if m["kind"] == "column_mask"}
            unmasked = sorted(f"{p['table_schema']}.{p['table_name']}.{p['column_name']}" for p in exposed
                              if (_cf(p["table_schema"]), _cf(p["table_name"]), _cf(p["column_name"])) not in masked)
            filters = sorted({f"{m['table_schema']}.{m['table_name']}" for m in policies if m["kind"] == "row_filter"})
            if unmasked:
                findings.append(finding(
                    "DB-08", f"No column mask attached to PII columns readable by '{role}'",
                    "HIGH", confidence, ";".join(unmasked[:3]),
                    f"{len(masked)} column mask(s) in the catalog; none attached to: {', '.join(unmasked)}. "
                    + (f"Row filters exist on {', '.join(filters)} (rows, not columns). " if filters else "")
                    + "ABAC policies' exempt principals are not visible in INFORMATION_SCHEMA; if ABAC is in use, review exemptions by hand.",
                    ["ALTER TABLE ... ALTER COLUMN ... SET MASK <fn> on each Restricted/Confidential column, or serve views.",
                     "Check every ABAC policy's EXCEPT list for the AI principal and its groups."],
                ))
    elif pii is None or readable is None:
        pass  # loader already emitted DB-06

    # ---- DB-04 masked layer ----
    if views is not None:
        signals = [v for v in views if str(v.get("has_masking_signal", "")).lower() in ("true", "t", "1")]
        invisible = [f"{v['table_schema']}.{v['table_name']}" for v in views if str(v.get("definition_visible", "true")).lower() in ("false", "f", "0")]
        masks = [m for m in (policies or []) if m["kind"] == "column_mask"]
        if not signals and not masks and invisible:
            unknowns.append({"check_id": "DB-06",
                             "reason": f"DB-04 not assessed: {len(invisible)} view definition(s) are not visible to the capturing user (VIEW_DEFINITION is NULL unless the viewer owns the view): {', '.join(invisible[:5])}.",
                             "action": "Capture masked_views.sql as the view owner or a metastore admin; an invisible definition is not evidence of an unmasked layer."})
        elif not signals and not masks:
            findings.append(finding(
                "DB-04", "No masked/governed view layer detected",
                "MEDIUM", confidence, "views",
                f"{len(views)} view(s) in the catalog, none with a masking signal in its definition, and no column masks attached. "
                "AI access appears to go straight at raw tables.",
                ["Stand up a curated schema of views (or column masks) as the only surface the AI principal can read."],
            ))
    # ---- DB-05 / DB-09 audit trail ----
    if audit is not None:
        schemas = {r["name"] for r in audit if r["kind"] == "system_schema"}
        grants_on = {}
        for r in audit:
            if r["kind"] == "grant":
                grants_on.setdefault(r["name"], []).append(r["detail"])
        if "access" not in schemas:
            findings.append(finding(
                "DB-05", "No audit trail of the AI principal's queries",
                "MEDIUM", confidence, "system.access",
                "The system.access schema (audit log, lineage) is not visible to the auditor: either system tables are not enabled for the account or the auditor lacks USE SCHEMA on it.",
                ["Enable system tables (Unity Catalog account) and grant USE CATALOG/USE SCHEMA/SELECT on system.access to an auditor group."],
            ))
        elif not grants_on.get("access"):
            findings.append(finding(
                "DB-05", "Audit log readable by admins only",
                "MEDIUM", "probable" if confidence == "confirmed" else confidence, "system.access.audit",
                "system.access exists but no grant on it was recorded: only account/metastore admins can read system.access.audit, so no one else reviews what the AI principal did.",
                ["GRANT USE SCHEMA, SELECT ON SCHEMA system.access TO <auditor group>."],
            ))
        problems = []
        if "query" not in schemas:
            problems.append("system.query (query history) is not visible: statement-level history for SQL warehouses is unavailable to the auditor")
        problems.append("system.query.history redacts statement_text for non-admins and covers SQL warehouses and serverless compute only; retention is 365 days")
        findings.append(finding(
            "DB-09", "Audit trail of the AI principal has known blind spots",
            "MEDIUM" if "query" not in schemas else "INFO", "probable" if confidence == "confirmed" else confidence, "system.query.history",
            "; ".join(problems) + ".",
            ["Grant an auditor group USE SCHEMA/SELECT on system.query; export system.access.audit to your SIEM for longer retention."],
        ))
    # ---- DB-ID-01 identity ----
    if ident is not None:
        kind = _kind(role)
        problems = []
        sev = "HIGH"
        if kind == "user":
            problems.append("the principal is a USER (email), not a service principal: the agent shares a human's identity, sessions, and audit trail")
        elif kind == "group":
            problems.append("the principal is a GROUP: every member's session is 'the agent' and vice versa")
        if groups:
            problems.append(f"member of {len(groups)} group(s): {', '.join(groups)}" + (f" ({len(nested)} through nesting: {', '.join(nested)})" if nested else "") + "; every grant to those groups is the agent's")
        owned = sorted({f"{g['level']} {obj(g)}" for g in (grants or []) if _cf(g.get("owner")) in owners_set})
        if owned:
            problems.append(f"owns {len(owned)} securable(s): {', '.join(owned[:5])} (owner of a catalog or schema manages every grant below it)")
        if manage:
            problems.append(f"holds MANAGE on {', '.join(manage)}: it can grant itself any privilege on those securables and everything below")
            sev = "CRITICAL"
        if problems:
            findings.append(finding(
                "DB-ID-01", f"AI principal '{role}' identity is wider than its direct grants",
                sev, confidence, role,
                "; ".join(problems) + ". Direct grants understate what this identity can do.",
                ["Run the agent as a dedicated service principal (applicationId) that is a member of no shared group and owns nothing.",
                 "Grant that service principal SELECT on curated views only."],
            ))
    # ---- DB-07 indirect paths to PII ----
    if grants is not None and pii is not None:
        pii_tables = {(p["table_schema"], p["table_name"]) for p in pii}
        pii_tables = {(_cf(s), _cf(n)) for s, n in pii_tables}
        indirect = sorted({f"{g['level']} {obj(g)}:{g['privilege_type']} {via(g)}" for g in mine
                           if g["privilege_type"].upper() in READ_PRIVS | WRITE_PRIVS | MANAGE_PRIVS
                           and (_cf(g["grantee"]) != role_cf or inherited(g))
                           and (g["level"] in ("SCHEMA", "CATALOG") or (_cf(g["schema_name"]), _cf(g["object_name"])) in pii_tables)})
        if indirect:
            findings.append(finding(
                "DB-07", f"Raw-to-curated boundary crossed by indirect paths for '{role}'",
                "HIGH", confidence, role,
                f"Indirect read/write paths to PII-bearing objects: {', '.join(indirect)}. Revoking the principal's direct grants would not close these.",
                ["Remove the principal from shared groups; revoke catalog/schema-level SELECT from groups it belongs to; never grant to 'account users'."],
            ))
    # ---- DB-10 external paths ----
    if ext is not None:
        rows = [e for e in ext if _cf(e["grantee"]) in principal_set]
        write = sorted({f"{e['kind']} {e['name']}:{e['privilege_type']} ({via({'grantee': e['grantee'], 'inherited_from': e.get('inherited_from', 'NONE')})})" for e in rows if e["privilege_type"].upper() in EXT_WRITE})
        read = sorted({f"{e['kind']} {e['name']}:{e['privilege_type']}" for e in rows if e["privilege_type"].upper() in EXT_READ})
        # volume privileges granted at catalog/schema level cascade to every volume underneath
        for g in mine:
            if g["level"] in ("CATALOG", "SCHEMA") and g["privilege_type"].upper() in VOLUME_PRIVS:
                target = write if g["privilege_type"].upper() == "WRITE VOLUME" else read
                target.append(f"{g['level']} {obj(g)}:{g['privilege_type']} ({via(g)}; cascades to every volume below)")
        write, read = sorted(set(write)), sorted(set(read))
        if write or read:
            findings.append(finding(
                "DB-10", f"AI principal '{role}' has paths outside Unity Catalog tables",
                "CRITICAL" if write else "HIGH", confidence, role,
                (f"Write paths: {', '.join(write)}. " if write else "") + (f"Read paths: {', '.join(read)}. " if read else "")
                + "WRITE FILES / WRITE VOLUME write to cloud storage directly; READ FILES / READ VOLUME bypass table-level masks.",
                ["Revoke external location, storage credential, and volume privileges from the principal and its groups."],
            ))

    raw_tables = []
    if grants is not None:
        seen = set()
        for g in sorted(mine, key=lambda x: (x["schema_name"] or "", x["object_name"] or "")):
            if g["level"] == "TABLE" and g["object_type"].upper() in BASE_TYPES and g["privilege_type"].upper() in READ_PRIVS:
                key = (g["schema_name"], g["object_name"])
                if key not in seen:
                    seen.add(key)
                    raw_tables.append({"schema": g["schema_name"], "table": g["object_name"]})
    plan_inputs = {
        "dialect": "databricks", "role": role, "principal_kind": _kind(role), "groups": groups, "nested_groups": nested,
        "raw_tables": raw_tables,
        "pii_columns": [{"schema": p["table_schema"], "table": p["table_name"], "column": p["column_name"], "type": p.get("data_type"), "tier": p["tier_floor"]} for p in (pii or [])],
        "write_grants": [{"level": g["level"], "object": obj(g), "privilege": g["privilege_type"], "grantee": g["grantee"]} for g in mine if g["privilege_type"].upper() in WRITE_PRIVS] if grants is not None else [],
        "external_objects": [{"kind": e["kind"], "name": e["name"], "privilege": e["privilege_type"], "grantee": e["grantee"]} for e in (ext or []) if _cf(e["grantee"]) in principal_set],
        "manage": manage if grants is not None else [],
        "inputs_present": {k: tables.get(k) is not None for k in PACK},
        "planner_supported": False,
    }
    return findings, plan_inputs
