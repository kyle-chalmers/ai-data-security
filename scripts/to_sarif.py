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
  suppressed            -> results with suppressions[{kind: external, justification: reason}]

Evidence strings are copied as-is: the evaluators already redact values, and this tool adds no
new content, so a SARIF file is exactly as shareable as the report it came from.
"""

import argparse
import json
import os
import sys

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


def location_for(finding):
    obj = finding.get("file") or finding.get("object") or ""
    if not obj:
        return []
    looks_like_path = ("/" in obj or "." in obj) and " " not in obj and not obj.startswith("~")
    if looks_like_path:
        uri = obj.lstrip("./") or obj
        return [{"physicalLocation": {"artifactLocation": {"uri": uri, "uriBaseId": "TARGET"}}}]
    return [{"logicalLocations": [{"fullyQualifiedName": obj, "kind": "object"}]}]


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
        "locations": location_for(finding),
        "partialFingerprints": {"ai-data-security/v1": finding.get("fingerprint", "")},
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
        res["suppressions"] = [{"kind": "external", "status": "accepted",
                                "justification": suppressed_reason or "suppressed via .ai-data-security-ignore"}]
    return res


def convert(inputs, checks, citations, tool_version):
    results, rules_used, notifications = [], {}, []
    target = None
    for blob in inputs:
        target = target or blob.get("target")
        for f in blob.get("findings", []):
            results.append(result_for(f, checks))
            rules_used[f.get("check_id", "UNKNOWN")] = True
        for s in blob.get("suppressed", []):
            check_id = (s.get("fingerprint") or "UNKNOWN").split(":", 1)[0]
            pseudo = {"check_id": check_id, "title": s.get("title", f"suppressed {check_id}"),
                      "severity": s.get("severity", "INFO"), "fingerprint": s.get("fingerprint", ""),
                      "file": (s.get("fingerprint") or "::").split(":")[1] if s.get("fingerprint") else ""}
            results.append(result_for(pseudo, checks, suppressed_reason=s.get("reason", "")))
            rules_used[check_id] = True
        for u in blob.get("unknowns", []):
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
            "originalUriBaseIds": {"TARGET": {"uri": (target.rstrip("/") + "/") if target else "./"}},
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
