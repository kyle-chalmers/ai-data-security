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
