#!/usr/bin/env python3
"""Deterministic verdicts for the ai-data-security dbt-governance-audit skill.

Reads a dbt project's YAML (dbt_project.yml, schema files under model-paths, packages.yml) with
NO warehouse connection and emits:

  DBT-01  a PII-tagged model is consumed by an exposure, and no masking package / masked model is
          declared in the project (MEDIUM, probable — the YAML declares intent, not enforcement)
  DBT-02  columns whose names match the four-tier-framework PII patterns but carry no PII tag
          (MEDIUM, probable; column names only)
  DBT-03  a YAML file that could not be parsed by the stdlib subset reader (UNKNOWN, fail-closed)
  DBT-04  INFO: masking packages declared (or none)

Every finding states that a missing tag is not proof of no PII. Stdlib only. Read-only except
the optional --emit-json path. Never prints data values (there are none in YAML declarations).
"""

import argparse
import datetime
import json
import os
import re
import sys

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, os.path.join(PLUGIN_ROOT, "scripts"))
from yaml_subset import yaml_subset_load  # noqa: E402  (stdlib-only, shipped with the plugin)
SCHEMA_VERSION = 1
TOOL_VERSION = "1"

# Mirrors reference/four-tier-framework.md (token-boundary matches), kept standalone on purpose.
COLUMN_PATTERNS = [
    (re.compile(r"(?i)(^|[_ ])(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?)([_ ]|$)"), "Restricted"),
    (re.compile(r"(?i)(^|[_ ])(card_number|pan|cvv|account_number|routing_number|iban)([_ ]|$)"), "Restricted"),
    (re.compile(r"(?i)(^|[_ ])(dob|birth_date|date_of_birth|diagnosis|medical)([_ ]|$)"), "Restricted"),
    (re.compile(r"(?i)(^|[_ ])(email|phone|mobile|address|first_name|last_name|full_name|ip_address)([_ ]|$)"), "Confidential"),
    (re.compile(r"(?i)(^|[_ ])(salary|income|compensation)([_ ]|$)"), "Confidential"),
]
PII_META_KEYS = ("contains_pii", "pii", "is_pii", "sensitive", "sensitivity", "classification", "data_classification")
PII_TAG_WORDS = ("pii", "sensitive", "restricted", "confidential")
MASKING_PACKAGES = ("dbt_snow_mask", "dbt-snow-mask", "dbt-snowmask", "dbt_snowmask", "dbt_privacy", "dbt-privacy",
                    "dbt_data_privacy", "snowflake_masking", "dbt_masking")
MASKED_NAME = re.compile(r"(?i)(mask|hash|redact|governed|curated|anonymi[sz]ed|pseudonym)")
MASKED_META_KEYS = ("masked", "masking", "masking_policy", "masking_policies", "is_masked", "pii_masked")
REF_CALL = re.compile(r"^(ref|source)\((.*)\)$", re.S)
REF_STR = re.compile(r"""['"]([^'"]+)['"]""")


def depends_on_model(entry):
    """Model/source name from one exposures.depends_on entry, or None when the entry is not a form
    this audit understands: ref('m'), ref('pkg', 'm'), ref('m', version=2), ref('m', v=2),
    source('src', 'table'). The LAST positional quoted string is the object name."""
    m = REF_CALL.match(str(entry).strip())
    if not m:
        return None
    positional = []
    for part in m.group(2).split(","):
        part = part.strip()
        if "=" in part and not part.startswith(("'", '"')):
            continue  # keyword argument such as version=2
        s = REF_STR.fullmatch(part)
        if not s:
            return None
        positional.append(s.group(1))
    return positional[-1] if positional else None


def declares_masking(node):
    """Explicit per-model masking declaration in meta (never a name heuristic)."""
    meta = node.get("meta") if isinstance(node, dict) else None
    if not isinstance(meta, dict):
        return False
    for k, v in meta.items():
        if str(k).lower() in MASKED_META_KEYS and v not in (False, None, "", "false", "no"):
            return True
    return False


def load_registry():
    with open(os.path.join(PLUGIN_ROOT, "reference", "citations.yml"), encoding="utf-8") as f:
        citations = json.load(f)["citations"]
    with open(os.path.join(PLUGIN_ROOT, "reference", "checks.yml"), encoding="utf-8") as f:
        checks = json.load(f)["checks"]
    return citations, checks


def load_suppressions(target):
    path = os.path.join(target, ".ai-data-security-ignore")
    entries = {}
    if not os.path.exists(path):
        return entries
    today = datetime.date.today()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            fingerprint = parts[0]
            expires, reason = None, ""
            for part in parts[1:]:
                if part.startswith("expires="):
                    expires = part.split("=", 1)[1]
                elif part.startswith("reason="):
                    reason = line.split("reason=", 1)[1]
            expired = False
            if expires is not None:
                try:
                    expired = datetime.date.fromisoformat(expires) < today
                except ValueError:
                    expired = True
            entries[fingerprint] = {"expires": expires, "reason": reason, "expired": expired}
    return entries


def finding(check_id, title, severity, confidence, obj, evidence, remediation, qualifier):
    caps = {"possible": "MEDIUM", "probable": "HIGH", "confirmed": "CRITICAL"}
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    if order.index(severity) > order.index(caps[confidence]):
        severity = caps[confidence]
    return {
        "check_id": check_id, "title": title, "severity": severity, "confidence": confidence,
        "file": obj, "evidence": evidence, "remediation": remediation, "rotate_first": False,
        "fingerprint": f"{check_id}:{obj}:{qualifier}",
    }


NOT_PROOF = "A missing tag is a missing declaration, not proof of no PII; the YAML cannot prove enforcement."


def is_pii_tagged(node):
    if not isinstance(node, dict):
        return False
    meta = node.get("meta")
    if isinstance(meta, dict):
        for k, v in meta.items():
            if str(k).lower() in PII_META_KEYS and (v is True or (isinstance(v, str) and v.lower() not in ("false", "no", "public", "internal", ""))):
                return True
    tags = node.get("tags")
    if isinstance(tags, list) and any(isinstance(tg, str) and any(w in tg.lower() for w in PII_TAG_WORDS) for tg in tags):
        return True
    if isinstance(tags, str) and any(w in tags.lower() for w in PII_TAG_WORDS):
        return True
    return False


def column_floor(name):
    for pattern, tier in COLUMN_PATTERNS:
        if pattern.search(name):
            return tier
    return None


def find_project(target):
    for root in (target, *[os.path.join(target, d) for d in sorted(os.listdir(target)) if os.path.isdir(os.path.join(target, d))]):
        candidate = os.path.join(root, "dbt_project.yml")
        if os.path.isfile(candidate):
            return root
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="dbt project root (or its parent)")
    parser.add_argument("--emit-json")
    args = parser.parse_args()
    target = os.path.abspath(args.target)
    citations, checks = load_registry()
    findings, unknowns = [], []

    root = find_project(target) if os.path.isdir(target) else None
    if not root:
        unknowns.append({"check_id": "DBT-03", "reason": f"no dbt_project.yml found under {target}.",
                         "action": "Point --target at the dbt project root; the audit did not run."})
        result = {"schema_version": SCHEMA_VERSION, "skill": "dbt-governance-audit", "target": target,
                  "tools": {"dbt_audit": TOOL_VERSION}, "findings": [], "unknowns": unknowns, "suppressed": [], "summary": {}}
        _emit(result, args)
        return 0

    def load_yaml(path, rel):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                return yaml_subset_load(f.read())
        except (OSError, ValueError) as exc:
            unknowns.append({"check_id": "DBT-03",
                             "reason": f"{rel} could not be parsed by the stdlib YAML-subset reader ({exc.__class__.__name__}); its declarations were not assessed.",
                             "action": "Simplify the file (no anchors, multi-line scalars, or tabs) or review it by hand; do not treat this as a pass."})
            return None

    project = load_yaml(os.path.join(root, "dbt_project.yml"), "dbt_project.yml") or {}
    model_paths = project.get("model-paths") if isinstance(project, dict) else None
    if not isinstance(model_paths, list) or not model_paths:
        model_paths = ["models"]

    # packages.yml
    packages = []
    pkg_path = os.path.join(root, "packages.yml")
    if os.path.isfile(pkg_path):
        pk = load_yaml(pkg_path, "packages.yml")
        if isinstance(pk, dict) and isinstance(pk.get("packages"), list):
            for item in pk["packages"]:
                if isinstance(item, dict):
                    name = item.get("package") or item.get("git") or item.get("local") or ""
                    packages.append(str(name))
    masking_pkgs = [p for p in packages if any(m in p.lower() for m in MASKING_PACKAGES)]

    tagged_models, untagged_pii, masked_models, exposures, n_models, n_columns, n_files = set(), [], set(), [], 0, 0, 0
    masked_declared, name_hints, bad_deps = set(), set(), {}
    for mp in model_paths:
        base = os.path.join(root, str(mp))
        if not os.path.isdir(base):
            continue
        for dirpath, dirs, names in os.walk(base):
            dirs[:] = [d for d in dirs if d not in (".git", "target", "dbt_packages", "node_modules")]
            for fn in sorted(names):
                if not fn.endswith((".yml", ".yaml")):
                    continue
                rel = os.path.relpath(os.path.join(dirpath, fn), root)
                n_files += 1
                data = load_yaml(os.path.join(dirpath, fn), rel)
                if not isinstance(data, dict):
                    continue
                nodes = []
                for key in ("models", "seeds", "snapshots"):
                    if isinstance(data.get(key), list):
                        nodes += [(key, n) for n in data[key] if isinstance(n, dict)]
                if isinstance(data.get("sources"), list):
                    for src in data["sources"]:
                        if isinstance(src, dict) and isinstance(src.get("tables"), list):
                            nodes += [("sources", tb) for tb in src["tables"] if isinstance(tb, dict)]
                for kind, node in nodes:
                    name = str(node.get("name", "?"))
                    n_models += 1
                    model_tagged = is_pii_tagged(node)
                    if MASKED_NAME.search(name):
                        name_hints.add(name)  # reported, never used as proof
                    if declares_masking(node):
                        masked_declared.add(name)
                    cols = node.get("columns") if isinstance(node.get("columns"), list) else []
                    any_col_tagged = False
                    for col in cols:
                        if not isinstance(col, dict):
                            continue
                        n_columns += 1
                        cname = str(col.get("name", ""))
                        col_tagged = is_pii_tagged(col)
                        any_col_tagged = any_col_tagged or col_tagged
                        floor = column_floor(cname)
                        if floor and not col_tagged and not model_tagged:
                            untagged_pii.append((rel, kind, name, cname, floor))
                    if model_tagged or any_col_tagged:
                        tagged_models.add(name)
                if isinstance(data.get("exposures"), list):
                    for ex in data["exposures"]:
                        if isinstance(ex, dict):
                            deps = ex.get("depends_on") if isinstance(ex.get("depends_on"), list) else []
                            refs = []
                            for d in deps:
                                nm = depends_on_model(d)
                                if nm is None:
                                    bad_deps.setdefault(rel, []).append(str(ex.get("name", "?")))
                                else:
                                    refs.append(nm)
                            exposures.append((rel, str(ex.get("name", "?")), str(ex.get("type", "?")), refs))
    for rel, names in sorted(bad_deps.items()):
        unknowns.append({"check_id": "DBT-03",
                         "reason": f"{rel}: exposure(s) {', '.join(sorted(set(names)))} have depends_on entries in a form this "
                                   "audit does not parse; their consumption of PII-tagged models was not assessed.",
                         "action": "Use ref('model'), ref('pkg', 'model'), ref('model', version=N) or source('src', 'table'), "
                                   "or review those exposures by hand."})

    # DBT-01: per exposure, a consumed PII-tagged model with no masking declared FOR THAT MODEL
    # (explicit meta on the model, or a masking package in the project). A model elsewhere in the
    # project that merely has "mask" in its name proves nothing about this exposure's lineage.
    if not masking_pkgs:
        for rel, ename, etype, refs in exposures:
            hits = sorted(r for r in refs if r in tagged_models and r not in masked_declared)
            if not hits:
                continue
            hinted = sorted(h for h in hits if h in name_hints)
            findings.append(finding(
                "DBT-01", f"Exposure '{ename}' ({etype}) consumes PII-tagged model(s) with no masking layer declared",
                "MEDIUM", "probable", f"{rel}:exposures.{ename}",
                f"Exposure {ename} depends on {', '.join(hits)}, which carry PII tags in the YAML and declare no masking "
                f"in their meta; packages.yml declares no masking package ({', '.join(packages) or 'no packages'}). "
                + (f"({', '.join(hinted)} is named like a masked layer, which is a hint, not a declaration.) " if hinted else "")
                + NOT_PROOF,
                [
                    "Route exposures of type application/analysis (where agents read) through a masked or curated model.",
                    "Declare the masking mechanism (dbt masking package or platform policy) and verify enforcement with db-access-audit.",
                ],
                ename,
            ))
    # DBT-02: likely-PII columns without a tag
    if untagged_pii:
        by_file = {}
        for rel, kind, name, cname, floor in untagged_pii:
            by_file.setdefault(rel, []).append((kind, name, cname, floor))
        for rel, items in sorted(by_file.items()):
            restricted = [f"{n}.{c}" for k, n, c, fl in items if fl == "Restricted"]
            confidential = [f"{n}.{c}" for k, n, c, fl in items if fl == "Confidential"]
            findings.append(finding(
                "DBT-02", f"{len(items)} likely-PII column(s) with no PII tag in {rel}",
                "MEDIUM", "probable", rel,
                (f"Restricted-pattern: {', '.join(restricted)}. " if restricted else "")
                + (f"Confidential-pattern: {', '.join(confidential)}. " if confidential else "")
                + "Names match the four-tier framework's PII patterns but carry no meta/tag declaration. " + NOT_PROOF,
                [
                    "Add meta: {contains_pii: true} (or your org's key) on the column or model so downstream tooling can see it.",
                    "Confirm with data-classification on an extract, or with db-access-audit DB-03 on the warehouse.",
                ],
                "untagged",
            ))
    # DBT-04: masking package inventory (INFO)
    findings.append(finding(
        "DBT-04", "Masking packages declared" if masking_pkgs else "No masking package declared in packages.yml",
        "INFO", "confirmed", "packages.yml",
        (f"Masking-related package(s): {', '.join(masking_pkgs)}. Presence is a declaration; attachment is verified by db-access-audit DB-08."
         if masking_pkgs else f"packages.yml lists {len(packages)} package(s), none masking-related; {len(masked_declared)} model(s) declare masking in meta; "
                              f"{len(name_hints)} model(s) are named like a masked layer (a hint only)."),
        ["Prefer platform masking policies verified by db-access-audit DB-08; a dbt package is one way to declare them."],
        "inventory",
    ))

    for f in findings:
        f["citations"] = [citations[k]["display"] for k in checks[f["check_id"]]["citations"]]
    suppressions = load_suppressions(root)
    active, suppressed = [], []
    for f in findings:
        entry = suppressions.get(f["fingerprint"])
        if entry and not entry["expired"]:
            suppressed.append({"fingerprint": f["fingerprint"], "title": f["title"], "severity": f["severity"],
                               "reason": entry["reason"], "expires": entry["expires"]})
        else:
            if entry and entry["expired"]:
                f["evidence"] += " (A suppression for this finding expired.)"
            active.append(f)
    result = {
        "schema_version": SCHEMA_VERSION, "skill": "dbt-governance-audit", "target": root,
        "tools": {"dbt_audit": TOOL_VERSION},
        "summary": {"yaml_files": n_files, "nodes": n_models, "columns": n_columns, "pii_tagged_nodes": sorted(tagged_models),
                    "masking_declared_nodes": sorted(masked_declared), "masked_name_hints": sorted(name_hints),
                    "exposures": [e[1] for e in exposures], "packages": packages, "masking_packages": masking_pkgs},
        "findings": active, "unknowns": unknowns, "suppressed": suppressed,
    }
    _emit(result, args)
    return 0


def _emit(result, args):
    output = json.dumps(result, indent=2)
    if args.emit_json:
        with open(args.emit_json, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
    else:
        print(output)


if __name__ == "__main__":
    raise SystemExit(main())
