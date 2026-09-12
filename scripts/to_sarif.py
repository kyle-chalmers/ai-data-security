#!/usr/bin/env python3
"""Convert ai-data-security JSON interchange (reference/finding-format.md) to SARIF 2.1.0.

Accepts one or more evaluator / quick-check JSON files and writes a single SARIF log that GitHub
Code Scanning and other SARIF consumers ingest. Deterministic, stdlib only, read-only on inputs.

Mapping
  finding.check_id      -> rule.id (rule metadata from reference/checks.yml + citations.yml)
  severity              -> result.level: CRITICAL/HIGH -> error, MEDIUM -> warning, LOW/INFO -> note
                           and properties.severity keeps the original word
  confidence            -> properties.confidence (SARIF has no native field; the cap stays visible)
  file / object         -> physicalLocation.artifactLocation.uri (relative to the target) —
                           warehouse objects that are not paths go to logicalLocations
  fingerprint           -> partialFingerprints["ai-data-security/v1"]
  unknowns              -> notifications in invocation.toolExecutionNotifications (level: warning)
  suppressed            -> results with suppressions[{kind: external}]; the free-text reason from
                           .ai-data-security-ignore is NOT copied (it is user-written and unredacted)

Evidence strings are copied as-is: the evaluators already redact values, and this tool adds no
new content and drops the one unredacted field (suppression reasons), so a SARIF file is as
shareable as the report it came from.
"""

import argparse
import json
import os
import sys
from urllib.parse import quote

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
SEVERITY_SCORE = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0", "LOW": "2.0", "INFO": "0.0"}


def load_registry():
    with open(os.path.join(PLUGIN_ROOT, "reference", "checks.yml"), encoding="utf-8") as f:
        checks = json.load(f)["checks"]
    with open(os.path.join(PLUGIN_ROOT, "reference", "citations.yml"), encoding="utf-8") as f:
        citations = json.load(f)["citations"]
    return checks, citations


def rule_for(check_id, checks, citations):
    spec = checks.get(check_id, {})
    cites = [citations[c] for c in spec.get("citations", []) if c in citations]
    return {
        "id": check_id,
        "name": spec.get("title", check_id).replace(" ", "")[:64] or check_id,
        "shortDescription": {"text": spec.get("title", check_id)},
        "fullDescription": {"text": spec.get("title", check_id)},
        "helpUri": cites[0]["url"] if cites else "https://github.com/kyle-chalmers/ai-data-security",
        "properties": {
            "skill": spec.get("skill"),
            "citations": [c["display"] for c in cites],
            "tags": ["security", "ai-data-security", spec.get("skill", "")],
        },
    }


LOGICAL_SKILLS = {"db-access-audit"}


def _uri(path):
    return quote(path, safe="/._-~")


def location_for(finding, checks):
    obj = finding.get("file") or finding.get("object") or ""
    if not isinstance(obj, str) or not obj:
        return []
    skill = finding.get("skill") or checks.get(str(finding.get("check_id", "")), {}).get("skill")
    if skill in LOGICAL_SKILLS or obj.startswith("~"):
        return [{"logicalLocations": [{"fullyQualifiedName": obj, "kind": "object"}]}]
    rel = obj.lstrip("/")
    while rel.startswith("./"):
        rel = rel[2:]
    return [{"physicalLocation": {"artifactLocation": {"uri": _uri(rel or obj), "uriBaseId": "TARGET"}}}]


def result_for(finding, checks, suppressed_reason=None):
    sev = finding.get("severity", "INFO")
    message = finding.get("title", finding.get("check_id", ""))
    evidence = finding.get("evidence")
    if evidence:
        message = f"{message}\n\n{evidence}"
    remediation = finding.get("remediation") or []
    if remediation:
        message += "\n\nRemediation:\n" + "\n".join(f"- {r}" for r in remediation)
    res = {
        "ruleId": finding.get("check_id", "UNKNOWN"),
        "level": LEVEL.get(sev, "note"),
        "message": {"text": message},
        "locations": location_for(finding, checks),
        "partialFingerprints": {"ai-data-security/v1": str(finding.get("fingerprint") or "")},
        "properties": {
            "severity": sev,
            "confidence": finding.get("confidence"),
            "security-severity": SEVERITY_SCORE.get(sev, "0.0"),
            "rotate_first": bool(finding.get("rotate_first")),
            "citations": finding.get("citations", []),
            "skill": finding.get("skill") or checks.get(finding.get("check_id", ""), {}).get("skill"),
        },
    }
    if finding.get("exposure"):
        res["properties"]["exposure"] = finding["exposure"]
    if suppressed_reason is not None:
        # The reason text is user-written and unredacted; never copy it into a shareable artifact.
        res["suppressions"] = [{"kind": "external", "status": "accepted",
                                "justification": "suppressed via .ai-data-security-ignore (reason withheld; see that file)"}]
    return res


def convert(inputs, checks, citations, tool_version):
    results, rules_used, notifications = [], {}, []
    target = None
    for blob in inputs:
        if not isinstance(blob, dict):
            continue
        target = target or blob.get("target")
        for f in blob.get("findings", []) if isinstance(blob.get("findings"), list) else []:
            if not isinstance(f, dict):
                continue
            f = dict(f)
            f.setdefault("skill", blob.get("skill"))
            results.append(result_for(f, checks))
            rules_used[str(f.get("check_id", "UNKNOWN"))] = True
        for s in blob.get("suppressed", []):
            if not isinstance(s, dict):
                continue
            fp = str(s.get("fingerprint") or "")
            # fingerprint = <check_id>:<object>:<qualifier>; the object may itself contain ':'.
            check_id, _, rest = fp.partition(":")
            obj, _, _qualifier = rest.rpartition(":")
            check_id = check_id or "UNKNOWN"
            pseudo = {"check_id": check_id, "title": s.get("title", f"suppressed {check_id}"),
                      "severity": s.get("severity", "INFO"), "fingerprint": fp,
                      "file": obj, "skill": blob.get("skill")}
            results.append(result_for(pseudo, checks, suppressed_reason=""))
            rules_used[check_id] = True
        for u in blob.get("unknowns", []) if isinstance(blob.get("unknowns"), list) else []:
            if not isinstance(u, dict):
                continue
            notifications.append({
                "level": "warning",
                "descriptor": {"id": u.get("check_id", "UNKNOWN")},
                "message": {"text": f"UNKNOWN: {u.get('reason', '')} Action: {u.get('action', '')}"},
            })
            rules_used[u.get("check_id", "UNKNOWN")] = True
    rules = [rule_for(rid, checks, citations) for rid in sorted(rules_used)]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "ai-data-security",
                "informationUri": "https://github.com/kyle-chalmers/ai-data-security",
                "version": tool_version,
                "rules": rules,
            }},
            "originalUriBaseIds": {"TARGET": {"uri": ("file://" + _uri(str(target).rstrip("/")) + "/") if target else "./"}},
            "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": notifications}],
            "results": results,
        }],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("inputs", nargs="+", help="evaluator / quick-check JSON files")
    parser.add_argument("-o", "--output", help="SARIF path (default stdout)")
    args = parser.parse_args()
    checks, citations = load_registry()
    with open(os.path.join(PLUGIN_ROOT, ".claude-plugin", "plugin.json"), encoding="utf-8") as f:
        tool_version = json.load(f).get("version", "0")
    blobs = []
    for path in args.inputs:
        with open(path, encoding="utf-8") as f:
            blobs.append(json.load(f))
    sarif = convert(blobs, checks, citations, tool_version)
    text = json.dumps(sarif, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
