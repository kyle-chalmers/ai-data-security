"""Google BigQuery — recorded `bq query --format=csv` outputs plus gcloud/bq JSON (see
sql/bigquery/README.md). PARTIAL by design: explicit object bindings + the project IAM policy.
What is not captured is said, never guessed: folder/org bindings, Google Group membership,
custom-role permissions, Fine-Grained Reader grants on policy-tag taxonomies.

Identity model: --role is an IAM member string (serviceAccount:, user:, group:). Bindings to
allUsers / allAuthenticatedUsers apply to everyone. A project-level role applies to every dataset
and table in the project (inherited); a dataset-level (SCHEMA) binding to every table in it.
"""

# Basic roles (owner/editor/viewer) are NOT table access: they map to dataset ACL special groups
# (projectOwners/Writers/Readers) only where a dataset kept those defaults, which OBJECT_PRIVILEGES
# does not show. They are reported as identity breadth (DB-ID-01) plus a DB-06, never as reads.
READ_ROLES = {"roles/bigquery.dataviewer", "roles/bigquery.dataeditor", "roles/bigquery.dataowner", "roles/bigquery.admin"}
WRITE_ROLES = {"roles/bigquery.dataeditor", "roles/bigquery.dataowner", "roles/bigquery.admin"}
JOB_ROLES = {"roles/bigquery.jobuser", "roles/bigquery.user", "roles/bigquery.admin"}
ADMIN_ROLES = {"roles/bigquery.admin", "roles/owner", "roles/editor", "roles/iam.securityadmin", "roles/resourcemanager.projectiamadmin"}
BASIC_ROLES = {"roles/owner", "roles/editor", "roles/viewer"}
STORAGE_WRITE = {"roles/storage.objectcreator", "roles/storage.objectadmin", "roles/storage.admin", "roles/storage.objectuser"}
INDIRECT_PREFIXES = ("group:", "domain:", "principalset:", "principal:")
MASKED_READER = {"roles/bigquerydatapolicy.maskedreader"}
LOG_ADMIN = {"roles/logging.admin", "roles/logging.configwriter", "roles/owner", "roles/editor"}
EVERYONE = {"allusers", "allauthenticatedusers"}
BASE_TYPES = {"BASE TABLE", "EXTERNAL", "CLONE", "SNAPSHOT", "MATERIALIZED VIEW", "MATERIALIZED_VIEW", "TABLE"}

PACK = {
    "grants": {"object_schema", "object_name", "object_type", "privilege_type", "grantee"},
    "pii_columns": {"table_schema", "table_name", "column_name", "field_path", "tier_floor"},
    "masked_views": {"table_schema", "table_name", "table_type", "definition_visible", "has_masking_signal"},
    "policy_tags": {"table_name", "field_path", "policy_tags", "data_policies"},
    "audit_logging": {"name", "setting"},
    "tables_manifest": {"tableId", "Type"},
}
JSON_INPUTS = {"iam_policy": "gcloud projects get-iam-policy <project> --format=json",
               "deny_policies": "gcloud iam policies list --attachment-point=cloudresourcemanager.googleapis.com/projects/<number> --kind=denypolicies --format=json",
               "sa_keys": "gcloud iam service-accounts keys list --iam-account=<sa> --managed-by=user --format=json (serviceAccount: principals only)",
               "log_bucket": "gcloud logging buckets describe _Default --location=global --project=<project> --format=json",
               "row_access_policies": "bq ls --row_access_policies --format=json <project>:<dataset>.<table> (concatenated with jq -s add)"}
OPTIONAL_JSON_INPUTS = {"sa_keys"}
CAPTURE = "bq query --format=csv --nouse_legacy_sql --max_rows=100000 < <substituted sql/bigquery/<file>.sql>  (grants.csv = grants_dataset.sql + grants_table.sql per table; see README)"
PRECONDITION = ("OBJECT_PRIVILEGES lists explicit bindings only and needs bigquery.datasets.get / bigquery.tables.getIamPolicy; "
                "folder/organization IAM, Google Group membership, custom-role permissions, and taxonomy IAM (Fine-Grained Reader) "
                "are not captured, so a clean result is partial by design.")


def _cf(v):
    return (v or "").strip().casefold()


def _kind(member):
    m = _cf(member)
    for prefix in ("serviceaccount:", "user:", "group:", "domain:", "principal:", "principalset:"):
        if m.startswith(prefix):
            return prefix[:-1]
    if m in EVERYONE:
        return "everyone"
    return "unknown"


def evaluate(role, tables, confidence, unknowns, finding):
    findings = []
    grants, pii, views = tables.get("grants"), tables.get("pii_columns"), tables.get("masked_views")
    ptags, audit, manifest = tables.get("policy_tags"), tables.get("audit_logging"), tables.get("tables_manifest")
    iam, sa_keys, log_bucket, rls, deny = tables.get("iam_policy"), tables.get("sa_keys"), tables.get("log_bucket"), tables.get("row_access_policies"), tables.get("deny_policies")
    role_cf = _cf(role)
    kind = _kind(role)
    matches = {role_cf} | EVERYONE

    def is_mine(member):
        return _cf(member) in matches

    # ---- project-level bindings (inherited by every dataset/table) ----
    project_roles, group_bindings, custom_roles, conditional = [], [], [], []
    if isinstance(iam, dict) and isinstance(iam.get("bindings"), list):
        for b in iam["bindings"]:
            if not isinstance(b, dict):
                continue
            r = str(b.get("role", ""))
            members = [str(m) for m in b.get("members", []) if isinstance(m, str)]
            if b.get("condition"):
                if any(is_mine(m) for m in members):
                    conditional.append(r)
                    unknowns.append({"check_id": "DB-06", "reason": f"iam_policy.json: the principal's binding for {r} carries an IAM condition ({str((b.get('condition') or {}).get('title', ''))[:60]}); it applies only when the condition is true, so it was EXCLUDED from effective access and not evaluated.",
                                     "action": "Review the condition expression by hand; if it is broad, treat the role as effective."})
                continue
            if any(is_mine(m) for m in members):
                project_roles.append(r)
                if not r.casefold().startswith("roles/"):
                    custom_roles.append(r)
            for m in members:
                if _kind(m) in ("group", "domain", "principalset", "principal"):
                    group_bindings.append((r, m))
    elif iam is not None:
        unknowns.append({"check_id": "DB-06", "reason": "iam_policy.json is not a policy object with a bindings list; project-level (inherited) access was not assessed.",
                         "action": f"Re-capture: {JSON_INPUTS['iam_policy']}"})
        iam = None
    if group_bindings and kind != "group":
        unknowns.append({"check_id": "DB-06",
                         "reason": f"{len(group_bindings)} project binding(s) go to Google Groups ({', '.join(sorted({m for _, m in group_bindings})[:5])}); whether {role} is a member is not visible here.",
                         "action": "Check membership in Cloud Identity / Google Groups; if the agent is a member, those roles apply to it."})
    if custom_roles:
        unknowns.append({"check_id": "DB-06", "reason": f"custom role(s) bound to the principal: {', '.join(sorted(set(custom_roles)))}; their permissions were not expanded.",
                         "action": "gcloud iam roles describe <role> and compare against bigquery.tables.getData / updateData."})
    pr_cf = {r.casefold() for r in project_roles}
    basic = sorted(r for r in project_roles if r.casefold() in BASIC_ROLES)
    if basic:
        unknowns.append({"check_id": "DB-06", "reason": f"basic role(s) {', '.join(basic)} at project level: these confer dataset READER/WRITER/OWNER only where a dataset kept its default special-group ACL (projectReaders/Writers/Owners), which OBJECT_PRIVILEGES does not show; not counted as table access here.",
                         "action": "bq show --format=prettyjson <dataset> for each dataset: look for specialGroup entries; replace basic roles with predefined ones."})
    if isinstance(deny, list):
        if deny:
            unknowns.append({"check_id": "DB-06", "reason": f"{len(deny)} IAM deny policy(ies) are attached to the project; deny rules override every allow role and were not evaluated, so allow-derived findings may overstate access.",
                             "action": "gcloud iam policies get for each; check whether the agent's principal or its permissions are denied."})
    elif deny is None:
        pass  # loader emitted DB-06 (missing capture): deny policies / principal access boundaries unknown
    else:
        unknowns.append({"check_id": "DB-06", "reason": "deny_policies.json is not a list; deny policies unknown.", "action": f"Re-capture: {JSON_INPUTS['deny_policies']}"})
    unknowns.append({"check_id": "DB-06", "reason": "principal access boundary policies and folder/organization-level deny or allow bindings are not captured; project-level allow findings are subject to them.",
                     "action": "Review the folder/organization IAM and PAB policies for the agent's principal."})
    can_read_all = bool(pr_cf & READ_ROLES)
    can_write_all = bool(pr_cf & WRITE_ROLES)
    can_run_jobs = bool(pr_cf & JOB_ROLES)

    # ---- explicit bindings (OBJECT_PRIVILEGES) ----
    mine = [g for g in grants if is_mine(g["grantee"])] if grants is not None else []
    if grants is not None:
        indirect_explicit = sorted({f"{g['object_type']} {g['object_name']}:{g['privilege_type']} → {g['grantee']}" for g in grants if _cf(g["grantee"]).startswith(INDIRECT_PREFIXES)})
        if indirect_explicit and kind != "group":
            unknowns.append({"check_id": "DB-06", "reason": f"explicit binding(s) to groups/domains/principal sets whose membership is not visible here: {', '.join(indirect_explicit[:6])}; if the agent is a member, those roles apply to it.",
                             "action": "Check the agent's Google Group / Cloud Identity memberships and workforce/workload identity pools."})

    def via(g):
        return "direct" if _cf(g["grantee"]) == role_cf else f"via '{g['grantee']}' (everyone)"

    if manifest is not None and views is not None:
        seen = {_cf(v["table_name"]) for v in views}
        missing_tables = sorted(str(m["tableId"]) for m in manifest if _cf(m.get("tableId")) and _cf(m.get("tableId")) not in seen)
        if missing_tables:
            unknowns.append({"check_id": "DB-06", "reason": f"capture incomplete: {len(missing_tables)} table(s) in the bq ls manifest have no row in masked_views.csv ({', '.join(missing_tables[:6])}); their bindings/columns may also be missing.",
                             "action": "Re-run the per-table capture loop under set -euo pipefail and check every exit status."})
    ds_read = [g for g in mine if g["object_type"].upper() == "SCHEMA" and g["privilege_type"].casefold() in READ_ROLES]
    ds_write = [g for g in mine if g["object_type"].upper() == "SCHEMA" and g["privilege_type"].casefold() in WRITE_ROLES]
    tbl_read = [g for g in mine if g["object_type"].upper() != "SCHEMA" and g["privilege_type"].casefold() in READ_ROLES]
    tbl_write = [g for g in mine if g["object_type"].upper() != "SCHEMA" and g["privilege_type"].casefold() in WRITE_ROLES]
    latent_note = "" if (can_run_jobs or iam is None) else " (no bigquery.jobUser/user role at project level in iam_policy.json: the principal cannot run queries in this project; access is latent unless it bills another project)"

    # ---- DB-01 ----
    if grants is not None or iam is not None:
        writes = sorted({f"project:{r}" for r in project_roles if r.casefold() in WRITE_ROLES}
                        | {f"dataset {g['object_name']}:{g['privilege_type']} ({via(g)})" for g in ds_write}
                        | {f"{g['object_schema']}.{g['object_name']}:{g['privilege_type']} ({via(g)})" for g in tbl_write})
        if writes:
            findings.append(finding(
                "DB-01", f"AI principal '{role}' holds write roles",
                "CRITICAL", confidence, role,
                f"Roles granting bigquery.tables.updateData (or broader): {', '.join(writes)}. A project-level role applies to every dataset and table in the project.",
                ["Bind the agent to roles/bigquery.dataViewer on a curated dataset (or authorized views) only; remove dataEditor/dataOwner/admin and the basic Owner/Editor roles."],
            ))
    # ---- DB-02 ----
    if grants is not None:
        types = {(_cf(v["table_name"])): (v.get("table_type") or "").upper() for v in (views or [])}
        base = sorted({f"{g['object_schema']}.{g['object_name']} ({via(g)})" for g in tbl_read
                       if g["object_type"].upper() != "VIEW" and types.get(_cf(g["object_name"]), g["object_type"].upper()) in BASE_TYPES | {"EXTERNAL"}})
        broad = sorted({f"dataset {g['object_name']}:{g['privilege_type']} ({via(g)})" for g in ds_read} | {f"project:{r}" for r in project_roles if r.casefold() in READ_ROLES})
        if base or broad:
            findings.append(finding(
                "DB-02", f"AI principal '{role}' reads base tables directly",
                "HIGH", confidence, role,
                (f"Read roles on tables: {', '.join(base)}. " if base else "") + (f"Read roles at {', '.join(broad)}: every current and future table underneath. " if broad else "") + latent_note.strip(),
                ["Grant dataViewer only on a curated dataset of authorized views; never at project level for an agent."],
            ))
    types = {_cf(v["table_name"]): (v.get("table_type") or "").upper() for v in (views or [])}
    readable_tables = {_cf(g["object_name"]) for g in tbl_read if types.get(_cf(g["object_name"]), g["object_type"].upper()) != "VIEW"}
    readable_views = sorted({g["object_name"] for g in tbl_read if types.get(_cf(g["object_name"]), g["object_type"].upper()) == "VIEW"})
    ds_readable = can_read_all or bool(ds_read)
    if readable_views:
        unknowns.append({"check_id": "DB-06", "reason": f"the principal reads view(s) {', '.join(readable_views)}: authorized-view/authorized-dataset relationships are not captured, so whether a view projects raw columns from datasets the principal cannot otherwise read is unknown; view columns are excluded from DB-03/DB-08 below.",
                         "action": "bq show --format=prettyjson <source dataset> → access[].view entries; read each view definition."})

    def readable(table):
        if types.get(_cf(table)) == "VIEW":
            return False
        return ds_readable or _cf(table) in readable_tables

    # ---- DB-03 / DB-08 ----
    exposed = []
    if pii is not None and (grants is not None or iam is not None):
        exposed = [p for p in pii if readable(p["table_name"])]
        tagged, datapol = {}, {}
        for t in (ptags or []):
            if t.get("policy_tags"):
                tagged[(_cf(t["table_name"]), _cf(t["field_path"]))] = t["policy_tags"]
            if t.get("data_policies"):
                datapol[(_cf(t["table_name"]), _cf(t["field_path"]))] = t["data_policies"]
        for tier, sev in (("Restricted", "HIGH"), ("Confidential", "MEDIUM")):
            cols = sorted(f"{p['table_schema']}.{p['table_name']}.{p['field_path']}" for p in exposed if p["tier_floor"] == tier)
            if cols:
                findings.append(finding(
                    "DB-03", f"{tier}-tier columns readable by '{role}'",
                    sev, confidence, ";".join(cols[:3]),
                    f"PII-named columns at {tier} floor on readable tables: {', '.join(cols)} (column names only; no data sampled). "
                    "Columns carrying a policy tag are listed under DB-08 with the tag; whether this principal holds Fine-Grained Reader on the tag is not visible here.",
                    ["Attach policy tags with a data policy (masking) to these columns, or serve authorized views that omit/hash them."],
                ))
        if ptags is not None and exposed:
            def key(p):
                return (_cf(p["table_name"]), _cf(p["field_path"]))
            untagged = sorted(f"{p['table_schema']}.{p['table_name']}.{p['field_path']}" for p in exposed if key(p) not in tagged and key(p) not in datapol)
            tagged_cols = sorted(f"{p['table_schema']}.{p['table_name']}.{p['field_path']}" for p in exposed if key(p) in tagged)
            datapol_cols = sorted(f"{p['table_schema']}.{p['table_name']}.{p['field_path']}" for p in exposed if key(p) in datapol and key(p) not in tagged)
            if untagged:
                findings.append(finding(
                    "DB-08", f"No policy tag or data policy on PII columns readable by '{role}'",
                    "HIGH", confidence, ";".join(untagged[:3]),
                    f"{len(tagged)} policy-tagged and {len(datapol)} data-policy-governed field(s) in the dataset; none on: {', '.join(untagged)}. "
                    + (f"Policy-tagged and readable (governed only if the principal lacks Fine-Grained Reader on the taxonomy, which is not captured): {', '.join(tagged_cols)}. " if tagged_cols else "")
                    + (f"Data-policy-governed (effective masking rule not evaluated): {', '.join(datapol_cols)}. " if datapol_cols else ""),
                    ["Apply policy tags from a taxonomy with a data policy (SHA-256 / nullify), or data governance tags with data policies, to each PII field; grant the agent Masked Reader at most, never Fine-Grained Reader."],
                ))
            if tagged_cols:
                unknowns.append({"check_id": "DB-06", "reason": f"policy tags protect {len(tagged_cols)} readable PII field(s) only if {role} lacks datacatalog.categoryFineGrainedReader on their taxonomies (granted at the policy-tag level); taxonomy IAM was not captured.",
                                 "action": "gcloud data-catalog taxonomies get-iam-policy <taxonomy> --location=<loc> (and per policy tag); any binding for the agent = raw access."})
            if datapol_cols:
                unknowns.append({"check_id": "DB-06", "reason": f"data policies govern {len(datapol_cols)} readable PII field(s); which masking rule applies to {role} (raw / hashed / nullified) depends on the data policy's IAM, which was not captured.",
                                 "action": "gcloud bigquery datapolicies describe / get-iam-policy for each data policy."})
    # ---- DB-04 ----
    if views is not None:
        view_rows = [v for v in views if (v.get("table_type") or "").upper() == "VIEW"]
        signals = [v for v in view_rows if str(v.get("has_masking_signal", "")).lower() in ("true", "t", "1")]
        invisible = [v["table_name"] for v in view_rows if str(v.get("definition_visible", "true")).lower() in ("false", "f", "0")]
        if not signals and (ptags is None or not ptags) and invisible:
            unknowns.append({"check_id": "DB-06", "reason": f"DB-04 not assessed: {len(invisible)} view definition(s) not visible to the capturing user: {', '.join(invisible[:5])}.",
                             "action": "Capture masked_views.sql as a principal with bigquery.tables.get on the views."})
        elif not signals and not (ptags or []):
            findings.append(finding(
                "DB-04", "No masked/governed layer detected",
                "MEDIUM", confidence, "views",
                f"{len(view_rows)} view(s) in the dataset, none with a masking signal in its definition, and no policy-tagged columns. AI access appears to go straight at raw tables.",
                ["Stand up a dataset of authorized views (or policy tags with data policies) as the only surface the agent can read."],
            ))
    # ---- DB-05 / DB-09 ----
    retention = None
    if isinstance(log_bucket, dict):
        retention = log_bucket.get("retentionDays")
    elif log_bucket is not None:
        unknowns.append({"check_id": "DB-06", "reason": "log_bucket.json is not a bucket object; audit-log retention unknown.", "action": f"Re-capture: {JSON_INPUTS['log_bucket']}"})
    if audit is not None:
        kv = {a["name"]: a["setting"] for a in audit}
        findings.append(finding(
            "DB-05", "Audit trail exists by default (BigQuery Data Access logs) — check retention and who reads it",
            "INFO", confidence, "cloudaudit.googleapis.com/data_access",
            "BigQuery Data Access audit logs are on by default and cannot be disabled; INFORMATION_SCHEMA.JOBS keeps 180 days and was readable by the auditor. "
            + (f"The _Default log bucket retains {retention} day(s)." if retention is not None else "Log-bucket retention was not captured."),
            ["Route BigQuery audit logs to a dedicated bucket or SIEM with the retention your policy needs; grant Logs Viewer to the reviewing team."],
        ))
        problems = []
        try:
            cache = int(kv.get("principal_cache_hit_jobs_last_30d", "0") or 0)
            total = int(kv.get("principal_jobs_last_30d", "0") or 0)
        except ValueError:
            cache, total = 0, 0
        if cache:
            problems.append(f"{cache} of the principal's {total} job(s) in the last 30 days (jobs billed to this project) were served from the results cache: a cached read re-reads data without a new table access record")
        if retention is not None and int(retention) < 90:
            problems.append(f"_Default log bucket retention is {retention} days (Data Access logs are lost after that unless routed elsewhere)")
        if not (pr_cf & {"roles/logging.viewer", "roles/logging.privatelogviewer"} or pr_cf & LOG_ADMIN):
            problems.append("no project-level Logs Viewer / Private Logs Viewer binding for the principal was seen (fine for the agent; make sure a reviewer has it)")
        if problems:
            findings.append(finding(
                "DB-09", "Audit trail of the AI principal has known blind spots",
                "MEDIUM" if (cache or (retention is not None and int(retention) < 90)) else "INFO", "probable" if confidence == "confirmed" else confidence, "INFORMATION_SCHEMA.JOBS",
                "; ".join(problems) + ".",
                ["Disable the results cache for the agent's jobs (useQueryCache=false) or accept cache hits as reads; extend log retention via a routed bucket."],
            ))
    elif audit is None and tables.get("audit_logging") is None:
        pass  # loader emitted DB-06 (typically: bigquery.jobs.listAll missing)
    # ---- DB-ID-01 ----
    problems, sev = [], "HIGH"
    if kind == "user":
        problems.append("the principal is a USER account: the agent shares a human's identity, sessions, and audit trail")
    elif kind == "group":
        problems.append("the principal is a GROUP: every member's session is 'the agent' and vice versa")
    elif kind == "unknown":
        problems.append("the principal is not a recognised IAM member string (serviceAccount:/user:/group:)")
    admin = sorted(r for r in project_roles if r.casefold() in ADMIN_ROLES)
    if admin:
        problems.append(f"holds project-level admin/basic role(s) {', '.join(admin)}: it can grant itself anything"); sev = "CRITICAL"
    if isinstance(sa_keys, list):
        user_keys = [k for k in sa_keys if isinstance(k, dict) and str(k.get("keyType", "")).upper() == "USER_MANAGED"]
        if user_keys:
            problems.append(f"{len(user_keys)} user-managed service-account key(s) exist: long-lived credentials that leave the agent's identity wherever the key file goes")
    elif sa_keys is not None:
        unknowns.append({"check_id": "DB-06", "reason": "sa_keys.json is not a list of keys; user-managed key exposure unknown.", "action": f"Re-capture: {JSON_INPUTS['sa_keys']}"})
    elif kind == "serviceaccount":
        unknowns.append({"check_id": "DB-06", "reason": "sa_keys.json was not captured for a service-account principal; whether user-managed (long-lived) keys exist is unknown.", "action": f"Capture: {JSON_INPUTS['sa_keys']}"})
    if basic:
        problems.append(f"holds basic role(s) {', '.join(basic)} at project level (dataset default ACLs may make these reads/writes on every dataset that kept them)")
        if any(r.casefold() in ("roles/owner", "roles/editor") for r in basic):
            sev = "CRITICAL"
    if iam is not None and problems:
        findings.append(finding(
            "DB-ID-01", f"AI principal '{role}' identity is wider than its object bindings",
            sev, confidence, role,
            "; ".join(problems) + ". Object-level bindings understate what this identity can do.",
            ["Run the agent as a dedicated service account with no user-managed keys (workload identity / impersonation), bound to dataViewer on a curated dataset only."],
        ))
    # ---- DB-07: inherited / dataset-level / everyone paths to PII ----
    if pii is not None and (grants is not None or iam is not None):
        pii_tables = {_cf(p["table_name"]) for p in pii}
        indirect = sorted({f"project:{r} (inherited by every dataset; subject to deny policies not captured)" for r in project_roles if r.casefold() in READ_ROLES | WRITE_ROLES}
                          | {f"dataset {g['object_name']}:{g['privilege_type']} ({via(g)})" for g in ds_read + ds_write}
                          | {f"{g['object_schema']}.{g['object_name']}:{g['privilege_type']} ({via(g)})" for g in tbl_read + tbl_write if _cf(g["grantee"]) != role_cf and _cf(g["object_name"]) in pii_tables})
        if indirect:
            findings.append(finding(
                "DB-07", f"Raw-to-curated boundary crossed by inherited or broad paths for '{role}'",
                "HIGH", confidence, role,
                f"Paths that reach PII-bearing tables without a table-level grant: {', '.join(indirect)}. OBJECT_PRIVILEGES alone would not have shown the project-level ones.",
                ["Remove project- and dataset-level read roles from the agent; bind it to specific authorized views. Never use allUsers/allAuthenticatedUsers on PII datasets."],
            ))
    # ---- DB-10: storage write roles, external tables ----
    if iam is not None or views is not None:
        storage = sorted(r for r in project_roles if r.casefold() in STORAGE_WRITE)
        externals = sorted(v["table_name"] for v in (views or []) if (v.get("table_type") or "").upper() == "EXTERNAL" and readable(v["table_name"]))
        if storage or externals:
            findings.append(finding(
                "DB-10", f"AI principal '{role}' has paths outside BigQuery storage",
                "CRITICAL" if storage else "HIGH", confidence, role,
                (f"Project-level Cloud Storage write role(s): {', '.join(storage)} — EXPORT DATA / extract jobs can write query results to a bucket. " if storage else "")
                + (f"Readable EXTERNAL tables (data lives in Cloud Storage/Drive/Bigtable, outside BigQuery's column-level controls): {', '.join(externals)}. " if externals else ""),
                ["Remove storage write roles from the agent; serve external data through native tables or authorized views."],
            ))
    # ---- row access policies (INFO) ----
    if isinstance(rls, list) and rls:
        findings.append(finding(
            "DB-08", f"{len(rls)} row access policy(ies) exist on the dataset's tables",
            "INFO", confidence, "row_access_policies",
            f"Row access policies on: {', '.join(sorted({str((p.get('rowAccessPolicyReference') or p.get('tableReference') or {}).get('tableId', '?')) for p in rls if isinstance(p, dict)}))}. Rows, not columns; query duration can leak filtered rows (BigQuery documents the side channel).",
            ["Keep RLS as defense in depth; column protection still needs policy tags or views."],
        ))

    plan_inputs = {
        "dialect": "bigquery", "role": role, "principal_kind": kind, "project_roles": sorted(project_roles),
        "raw_tables": sorted({g["object_name"] for g in tbl_read if g["object_type"].upper() != "VIEW"}),
        "pii_columns": [{"schema": p["table_schema"], "table": p["table_name"], "column": p["field_path"], "type": p.get("data_type"), "tier": p["tier_floor"]} for p in (pii or [])],
        "conditional_roles": sorted(conditional), "basic_roles": basic,
        "write_grants": [{"object": f"{g['object_schema']}.{g['object_name']}", "privilege": g["privilege_type"], "grantee": g["grantee"]} for g in tbl_write + ds_write],
        "inputs_present": {k: tables.get(k) is not None for k in list(PACK) + list(JSON_INPUTS)},
        "planner_supported": False, "partial_by_design": True,
    }
    plan_inputs["raw_tables"] = [{"schema": "", "table": t} for t in plan_inputs["raw_tables"]]
    return findings, plan_inputs
