#!/usr/bin/env python3
"""Unit tests for the deterministic matchers — locks the permission-glob semantics and the
fail-closed suppression-expiry behavior. Stdlib only; run by tests/run-fixture-checks.sh."""

import importlib.util
import os
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    assert spec is not None and spec.loader is not None, rel
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


eval_secrets = load("eval_secrets", "skills/secrets-scanner/scripts/eval_secrets.py")

CASES = [
    # (pattern, relpath, expected deny_covers)
    ("./.env", ".env", True),
    ("./.env", "sub/.env", False),          # ./ anchors at project root
    (".env", ".env", True),
    (".env", "a/b/.env", True),             # bare name matches at any depth
    (".env", "prod.env", False),            # never a substring match
    ("**/.env", "a/b/.env", True),
    ("**/.env", ".env", True),              # zero segments allowed
    ("**/.env", "prod.env", False),         # the over-match bug this file locks against
    ("./secrets/**", "secrets/a/b.pem", True),
    ("./secrets/**", "notsecrets/a.pem", False),
    ("./.env.*", ".env.local", True),
    ("./.env.*", ".environment", False),
]

failures = []
for pattern, relpath, expected in CASES:
    got = eval_secrets.deny_covers(pattern, relpath)
    if got is not expected:
        failures.append(f"deny_covers({pattern!r}, {relpath!r}) = {got}, expected {expected}")

# AC-01 deny-rule spelling equivalence (permeval): every documented anchor prefix normalizes to the
# same protected path; non-Read rules and unrelated paths never satisfy a target.
permeval_ac01 = load("permeval_ac01", "skills/ai-config-audit/scripts/permeval.py")
DENY_CASES = [
    ("Read(.env)", ".env"),
    ("Read(**/.env)", ".env"),
    ("Read(./.env)", ".env"),
    ("Read(/.env)", ".env"),
    ("Read(//**/.env)", ".env"),
    ("Read(./secrets/**)", "secrets/**"),
    ("Read(//**/secrets/**)", "secrets/**"),
    ("Read(.env.*)", ".env.*"),
    ("Read(prod.env)", "prod.env"),          # a different path, never equal to .env
    ("Edit(.env)", None),                     # only Read rules count for AC-01
    ("Bash(cat .env)", None),
    ("Read( .env )", None),                   # inner whitespace is a different (useless) path
    ("Read()", None),
]
for rule, expected in DENY_CASES:
    got = permeval_ac01.deny_rule_target(rule)
    if got != expected:
        failures.append(f"deny_rule_target({rule!r}) = {got!r}, expected {expected!r}")
if not permeval_ac01.deny_target_satisfied(".env", ["Read(**/.env)"]):
    failures.append("deny_target_satisfied: Read(**/.env) should satisfy .env")
if permeval_ac01.deny_target_satisfied(".env", ["Read(prod.env)", "Read(.env.*)"]):
    failures.append("deny_target_satisfied: prod.env / .env.* must not satisfy .env")
# Stronger globs subsume the requirement; weaker or unrelated ones never do.
for target, rules, expected in [
    (".env", ["Read(.env*)"], True),
    (".env.*", ["Read(.env*)"], True),
    (".env.*", ["Read(**/.env*)"], True),
    ("secrets/**", ["Read(secrets/*)"], False),      # single segment: misses secrets/nested/b.key
    ("secrets/**", ["Read(**/secrets/**)"], True),
    ("secrets/**", ["Read(secret/**)"], False),
    (".env", ["Read( .env )"], False),
    (".env", ["Read(.env/**)"], False),
]:
    got = permeval_ac01.deny_target_satisfied(target, rules)
    if got is not expected:
        failures.append(f"deny_target_satisfied({target!r}, {rules!r}) = {got}, expected {expected}")

# DESCRIBE USER column-name variants and null-falls-back-to-default (Snowflake renders either
# `value/default` or `property_value/property_default`; an unset DEFAULT_SECONDARY_ROLES means [ALL]).
eval_grants_sf = load("eval_grants_sf", "skills/db-access-audit/scripts/eval_grants.py")
desc_a = eval_grants_sf._desc_user([
    {"property": "TYPE", "value": "SERVICE_AGENT", "default": "null"},
    {"property": "DEFAULT_SECONDARY_ROLES", "value": "null", "default": "[ALL]"},
])
desc_b = eval_grants_sf._desc_user([
    {"property": "TYPE", "property_type": "String", "property_value": "PERSON", "property_default": "null"},
    {"property": "DEFAULT_SECONDARY_ROLES", "property_type": "String", "property_value": "[]", "property_default": "[ALL]"},
])
if desc_a.get("TYPE") != "SERVICE_AGENT" or "ALL" not in desc_a.get("DEFAULT_SECONDARY_ROLES", ""):
    failures.append(f"_desc_user value/default variant: {desc_a}")
if desc_b.get("TYPE") != "PERSON" or desc_b.get("DEFAULT_SECONDARY_ROLES") != "[]":
    failures.append(f"_desc_user property_value variant: {desc_b}")

# v0.5: provenance pin detection, shared YAML-subset reader, Toolbox statement classes, IBAN mod-97, dbt refs.
pv = load("permeval_v05", "skills/ai-config-audit/scripts/permeval.py")
for tokens, expect_flag in [
    (["npx", "-y", "@example/warehouse-mcp"], True),
    (["npx", "-y", "@example/warehouse-mcp@1.4.2"], False),
    (["npx", "@example/warehouse-mcp@^1.4.0"], True),
    (["uvx", "snowflake-labs-mcp"], True),
    (["uvx", "snowflake-labs-mcp@2.0.0"], False),
    (["uvx", "--from", "snowflake-labs-mcp==2.0.0", "mcp-server-snowflake"], False),
    (["pipx", "run", "example-mcp==1.2.3"], False),
    (["pipx", "run", "example-mcp"], True),
    (["npx", "some-pkg@latest"], True),
    (["pnpm", "dlx", "tool@3.1.0"], False),
    (["npx", "github:org/repo"], True),
    (["npx", "git+https://github.com/org/repo.git#main"], True),
    (["npx", "git+https://github.com/org/repo.git#" + "a" * 40], False),
    (["node", "server.js"], False),
    (["uv", "run", "postgres-mcp"], False),          # uv run is a local project, not a fetch
    ([], False),
]:
    got = pv._unpinned(tokens) is not None
    if got is not expect_flag:
        failures.append(f"_unpinned({tokens!r}) flagged={got}, expected {expect_flag}")
for sql, expect in [
    ("SELECT 1", "read"),
    ("-- note\nSELECT a FROM t", "read"),
    ("/* c */ DELETE FROM t", "write"),
    ("WITH x AS (DELETE FROM t RETURNING *) SELECT count(*) FROM x", "write"),
    ("WITH x AS (SELECT 1) SELECT * FROM x", "read"),
    ("SELECT * INTO new_t FROM t", "read"),  # INTO without a write keyword: still a read by the matcher (documented limit)
    ("SET search_path TO app", "unclassified"),
    ("", "unclassified"),
]:
    got = pv.classify_statement(sql)
    if got != expect:
        failures.append(f"classify_statement({sql!r}) = {got}, expected {expect}")
y = pv.yaml_subset_load("a: 1\nlist:\n  - Insert: True\n  - Select: False\nnested:\n  k: 'v'\n  flow: [x, y]\n  m: {contains_pii: true}\n  d: |\n    line one\n    line two\nvar: ${PG_USER}\n")
if not (y.get("a") == "1" and y["list"][0] == {"Insert": True} and y["nested"]["k"] == "v" and y["nested"]["flow"] == ["x", "y"]
        and y["nested"]["m"] == {"contains_pii": True} and "line two" in y["nested"]["d"] and y["var"] == "${PG_USER}"):
    failures.append(f"yaml_subset_load basic shape: {y!r}")
for hostile in ["bad:\n  - x\n  y: 2\n", "models: [\n", "a: &x 1\n", "a: *x\n", "a: 'unterminated\n",
                "a:\n\t- x\n", "a: {b: [1]}\n", "a: 1\n---\nb: 2\n", "a: !!python/object x\n", "- x\nb: 1\n"]:
    try:
        pv.yaml_subset_load(hostile)
        failures.append(f"yaml_subset_load accepted hostile input {hostile!r}")
    except ValueError:
        pass
    except Exception as exc:  # noqa: BLE001 — anything but ValueError is a crash path
        failures.append(f"yaml_subset_load crashed ({exc.__class__.__name__}) on {hostile!r}")
cl = load("classify_v05", "skills/data-classification/scripts/classify_hints.py")
for cand, ok in [("GB82WEST12345698765432", True), ("DE89370400440532013000", True), ("GB82WEST12345698765433", False), ("XX00", False)]:
    if cl.iban_valid(cand) is not ok:
        failures.append(f"iban_valid({cand}) != {ok}")
db = load("dbt_v05", "skills/dbt-governance-audit/scripts/dbt_audit.py")
for entry, expect in [("ref('m')", "m"), ('ref("m")', "m"), ("ref('pkg', 'm')", "m"), ("ref('m', version=2)", "m"),
                      ("ref('m', v=2)", "m"), ("source('src', 'tbl')", "tbl"), ("ref(var('x'))", None), ("metric('x')", None), ("", None)]:
    got = db.depends_on_model(entry)
    if got != expect:
        failures.append(f"depends_on_model({entry!r}) = {got!r}, expected {expect!r}")

# Fail-closed expiry: unparseable AND blank expires= must both count as expired.
# Blank expires= (fail-open) was an edge-hardening finding — locked here across all evaluators.
permeval = load("permeval", "skills/ai-config-audit/scripts/permeval.py")
classify = load("classify_hints", "skills/data-classification/scripts/classify_hints.py")
eval_grants = load("eval_grants", "skills/db-access-audit/scripts/eval_grants.py")

for mod in (eval_secrets, permeval, classify, eval_grants):
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, ".ai-data-security-ignore"), "w", encoding="utf-8") as f:
            f.write("X:a:b expires=not-a-date reason=malformed\n")
            f.write("X:c:d expires= reason=blank fails open\n")
            f.write("X:e:f expires=2099-01-01 reason=valid future\n")
        e = mod.load_suppressions(tmp)
        if not e["X:a:b"]["expired"]:
            failures.append(f"{mod.__name__}: malformed expires= did not fail closed")
        if not e["X:c:d"]["expired"]:
            failures.append(f"{mod.__name__}: blank expires= failed OPEN (must fail closed)")
        if e["X:e:f"]["expired"]:
            failures.append(f"{mod.__name__}: valid future expires= wrongly expired")

# ReDoS guard: the EMAIL regex must scan a long adversarial input in well under a second.
import time  # noqa: E402
adversarial = ("a" * 60000) + "@" + ("a" * 60000)
t0 = time.perf_counter()
classify.EMAIL.findall(adversarial)
elapsed = time.perf_counter() - t0
if elapsed > 1.0:
    failures.append(f"EMAIL regex took {elapsed:.2f}s on adversarial input (ReDoS not fixed)")
# ...and still matches real addresses
for addr in ("a@example.com", "john.doe+tag@sub.example.co.uk"):
    if not classify.EMAIL.search(addr):
        failures.append(f"EMAIL regex no longer matches {addr}")

# Filename-heuristic precision: the word "secret"/"payment"/"user" in a SOURCE filename must not
# floor it by name alone (content still decides); genuine data/config files still floor by name.
with tempfile.TemporaryDirectory() as tmp:
    def floor_of(name, body="nothing sensitive here\n"):
        p = os.path.join(tmp, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(body)
        return classify.classify_file(p, name)["floor"]

    if floor_of("eval_secrets.py") != "Internal":
        failures.append("source file eval_secrets.py floored above Internal by filename alone")
    if floor_of("payment_service.go") != "Internal":
        failures.append("source file payment_service.go floored by filename alone")
    if floor_of("credentials.json") != "Restricted":
        failures.append("data file credentials.json no longer floors Restricted by name")
    if floor_of(".env") != "Restricted":
        failures.append(".env no longer floors Restricted by name")
    # content still wins inside source: a real SSN in a .py is Restricted regardless of name
    if floor_of("helper.py", "user record ssn 078-05-1120\n") != "Restricted":
        failures.append("content SSN in a .py was not caught (extension skip over-applied)")

if failures:
    print("MATCHER TESTS: FAIL")
    for f in failures:
        print("  " + f)
    sys.exit(1)
print(f"MATCHER TESTS: PASS ({len(CASES)} glob cases + expiry fail-closed x4 + ReDoS guard + filename precision)")
