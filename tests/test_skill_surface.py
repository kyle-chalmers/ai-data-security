#!/usr/bin/env python3
"""Locks the human-facing surface of the skills: short front pages, trigger phrases, narration,
a next step, a glossary entry for every check, and a capture README for every warehouse pack.
These are prose rules, so without a test they drift the first time a skill is edited.
Stdlib only; run by dev/validate.sh."""

import json
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SKILLS = os.path.join(ROOT, "skills")
MAX_BODY_LINES = 80

failures = []


def check(ok, message):
    print(("OK: " if ok else "FAIL: ") + message)
    if not ok:
        failures.append(message)


def split_skill(path):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if not text.startswith("---\n"):
        return {}, text
    _, front, body = text.split("---\n", 2)
    fields = {}
    for line in front.splitlines():
        key, _, value = line.partition(": ")
        fields[key.strip()] = value.strip()
    return fields, body


skill_dirs = sorted(d for d in os.listdir(SKILLS) if os.path.isfile(os.path.join(SKILLS, d, "SKILL.md")))
check(len(skill_dirs) > 0, f"found {len(skill_dirs)} skills")

for name in skill_dirs:
    fields, body = split_skill(os.path.join(SKILLS, name, "SKILL.md"))
    lines = len(body.splitlines())
    check(lines <= MAX_BODY_LINES, f"{name}: SKILL.md body is {lines} lines (cap {MAX_BODY_LINES}); move depth to a sibling file")
    desc = fields.get("description", "")
    check("Use when" in desc, f"{name}: description says when to use it (\"Use when ...\")")
    # An unquoted YAML scalar cannot contain ": "; quoting keeps colons safe for every parser.
    quoted = len(desc) > 1 and desc[0] == desc[-1] and desc[0] in "'\""
    check(quoted or ": " not in desc, f"{name}: description is quoted or free of ': '")
    check("reference/narration.md" in body, f"{name}: points at the narration contract")
    check("Next:" in body, f"{name}: ends a run with a 'Next:' step")

# Every check ID in the registry has a glossary row, and the generated table is current.
with open(os.path.join(ROOT, "reference", "checks.yml"), encoding="utf-8") as fh:
    check_ids = list(json.load(fh)["checks"])
with open(os.path.join(ROOT, "docs", "glossary.md"), encoding="utf-8") as fh:
    glossary = fh.read()
missing = [cid for cid in check_ids if f"`{cid}`" not in glossary]
check(not missing, f"docs/glossary.md covers all {len(check_ids)} check IDs" + (f" (missing: {', '.join(missing)})" if missing else ""))
gen = subprocess.run([sys.executable, os.path.join(ROOT, "dev", "gen_glossary.py"), "--check"],
                     capture_output=True, text=True)
check(gen.returncode == 0, "docs/glossary.md check table matches reference/checks.yml (dev/gen_glossary.py --check)")

# Every warehouse pack has a capture README and a section in packs.md.
sql_root = os.path.join(SKILLS, "db-access-audit", "sql")
with open(os.path.join(SKILLS, "db-access-audit", "packs.md"), encoding="utf-8") as fh:
    packs = fh.read()
for dialect in sorted(os.listdir(sql_root)):
    if not os.path.isdir(os.path.join(sql_root, dialect)):
        continue
    check(os.path.isfile(os.path.join(sql_root, dialect, "README.md")), f"sql/{dialect}/README.md exists")
    check(re.search(rf"^## {re.escape(dialect)}\b", packs, re.M) is not None, f"packs.md has a '## {dialect}' section")

if failures:
    print(f"\n{len(failures)} skill-surface check(s) failed")
    sys.exit(1)
print("\nskill surface: all checks passed")
