#!/usr/bin/env bash
# Deterministic fixture assertions for ai-data-security. No LLM calls.
# Bidirectional: a missing expected finding is a false-negative regression;
# an unexpected finding on clean paths is a false-positive regression.
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1
fail=0
step() { echo; echo "==> $1"; }

# Portable bounded run: timeout (GNU/Linux) -> gtimeout (macOS coreutils) -> pure-shell poll.
# Returns 124 if the command exceeds the deadline.
run_bounded() {
  local secs="$1"; shift
  if command -v timeout >/dev/null 2>&1; then timeout "$secs" "$@"; return $?; fi
  if command -v gtimeout >/dev/null 2>&1; then gtimeout "$secs" "$@"; return $?; fi
  "$@" & local pid=$! i=0
  while kill -0 "$pid" 2>/dev/null; do
    sleep 1; i=$((i + 1))
    if [ "$i" -ge "$secs" ]; then kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; return 124; fi
  done
  wait "$pid"
}

step "reference consistency: checks.yml -> citations.yml + fixtures"
if ! jq -e --slurpfile cites reference/citations.yml '
    [.checks | to_entries[]
     | select((.value.citations - ($cites[0].citations | keys)) != [] or (.value.fixtures | length) == 0)
     | .key] == []' reference/checks.yml >/dev/null; then
  echo "FAIL: a check in checks.yml cites an unknown citation key or has no fixture"
  jq -r --slurpfile cites reference/citations.yml '
    .checks | to_entries[]
    | select((.value.citations - ($cites[0].citations | keys)) != [] or (.value.fixtures | length) == 0)
    | "  offending check: \(.key)"' reference/checks.yml
  fail=1
else
  echo "OK: every check cites known citations and names at least one fixture"
fi

step "reference provenance: every citation has string published/accessed/status; no check cites a withdrawn entry; no unused entries"
PROSE_ONLY='["owasp-llm01","atlas-aml-t0051-001"]'  # cited in SECURITY.md prose, per citations.yml's own rule
if ! jq -e '[.citations | to_entries[] | select(((.value.published | type) != "string") or (.value.published == "") or ((.value.accessed | type) != "string") or (.value.accessed == "") or ((.value.status // "") | IN("current","superseded","withdrawn") | not)) | .key] == []' reference/citations.yml >/dev/null; then
  echo "FAIL: a citation lacks a non-empty string published/accessed or has an invalid status"
  jq -r '.citations | to_entries[] | select(((.value.published | type) != "string") or (.value.published == "") or ((.value.accessed | type) != "string") or (.value.accessed == "") or ((.value.status // "") | IN("current","superseded","withdrawn") | not)) | "  offending citation: \(.key)"' reference/citations.yml
  fail=1
elif ! jq -e --slurpfile cites reference/citations.yml --argjson prose "$PROSE_ONLY" '
    ([.checks[].citations[]] + $prose | unique) as $used
    | [$cites[0].citations | keys[] | select(. as $k | $used | index($k) | not)] == []' reference/checks.yml >/dev/null; then
  echo "FAIL: a citation is neither referenced by a check nor in the prose-only allowlist"
  jq -r --slurpfile cites reference/citations.yml --argjson prose "$PROSE_ONLY" '
    ([.checks[].citations[]] + $prose | unique) as $used
    | $cites[0].citations | keys[] | select(. as $k | $used | index($k) | not) | "  unused citation: \(.)"' reference/checks.yml
  fail=1
elif ! jq -e --slurpfile cites reference/citations.yml '
    [.checks | to_entries[] | select([.value.citations[] | $cites[0].citations[.].status == "withdrawn"] | any) | .key] == []' reference/checks.yml >/dev/null; then
  echo "FAIL: a check cites a withdrawn citation"
  fail=1
else
  echo "OK: every citation carries provenance fields and no check cites a withdrawn entry"
fi

step "doctor without gitleaks (PATH mocked): secrets lane must be UNKNOWN, exit 0, no child output echoed"
DOCTMP="$(mktemp -d)"
NOGL_BIN="$DOCTMP/bin"; mkdir -p "$NOGL_BIN"
ln -s "$(command -v python3)" "$NOGL_BIN/python3"
# A hostile "psql" on PATH prints a secret-shaped line: doctor must not echo it as a version.
printf '#!/bin/sh\necho "AKIAIOSFODNN7EXAMPLE token=hunter2 version 99.9.9"\n' > "$NOGL_BIN/psql"; chmod +x "$NOGL_BIN/psql"
if PATH="$NOGL_BIN" python3 skills/doctor/scripts/doctor.py --home "$DOCTMP" --format json > "$DOCTMP/doc.json"; then
  if jq -e '(.tools.gitleaks.present | not) and (.capabilities | any(.skill == "secrets-scanner" and .status == "UNKNOWN")) and (.tools.psql.version == "99.9.9") and ([tostring | test("AKIA|hunter2")] == [false])' "$DOCTMP/doc.json" >/dev/null; then
    echo "OK: doctor without gitleaks -> secrets-scanner UNKNOWN; hostile tool output not echoed (version token only)"
  else
    echo "FAIL: doctor without gitleaks did not report UNKNOWN or echoed child output"; fail=1
  fi
else
  echo "FAIL: doctor exited non-zero without gitleaks"; fail=1
fi
rm -rf "$DOCTMP"

step "SARIF edge cases: colon-bearing DB fingerprint, suppression reason withheld, logical location for warehouse objects"
SARTMP="$(mktemp -d)"
cat > "$SARTMP/db.json" <<'JSON'
{"schema_version":1,"skill":"db-access-audit","target":"snowflake://fixture","tools":{"eval_grants":"2"},
 "findings":[{"check_id":"DB-03","title":"PII column readable","severity":"HIGH","confidence":"confirmed","object":"PROD.RAW.CUSTOMERS:EMAIL","evidence":"column readable","remediation":["mask it"],"citations":["x"],"fingerprint":"DB-03:PROD.RAW.CUSTOMERS:EMAIL:restricted"}],
 "unknowns":[],
 "suppressed":[{"fingerprint":"DB-01:PROD.RAW.ORDERS:INSERT","title":"write grant","severity":"CRITICAL","reason":"SECRET-REASON-VALUE-xyz","expires":null}]}
JSON
python3 scripts/to_sarif.py "$SARTMP/db.json" -o "$SARTMP/db.sarif"
if jq -e '([tostring | test("SECRET-REASON-VALUE")] == [false])
  and (.runs[0].results | any(.partialFingerprints["ai-data-security/v1"] == "DB-01:PROD.RAW.ORDERS:INSERT" and (.locations[0].logicalLocations[0].fullyQualifiedName == "PROD.RAW.ORDERS") and (.suppressions | length == 1)))
  and (.runs[0].results | any(.ruleId == "DB-03" and (.locations[0].logicalLocations[0].fullyQualifiedName == "PROD.RAW.CUSTOMERS:EMAIL")))
  and (.runs[0].originalUriBaseIds.TARGET.uri | endswith("/"))' "$SARTMP/db.sarif" >/dev/null; then
  echo "OK: SARIF withholds suppression reasons, keeps colon-bearing objects intact, uses logical locations for DB objects"
else
  echo "FAIL: SARIF edge cases"; jq -c '.runs[0].results[] | {ruleId, loc:.locations[0], fp:.partialFingerprints}' "$SARTMP/db.sarif"; fail=1
fi
printf '[1, "not-an-object"]\n' > "$SARTMP/junk.json"
if python3 scripts/to_sarif.py "$SARTMP/junk.json" -o "$SARTMP/junk.sarif" && jq -e '.runs[0].results == []' "$SARTMP/junk.sarif" >/dev/null; then
  echo "OK: SARIF tolerates a malformed interchange blob (empty run, no crash)"
else
  echo "FAIL: SARIF crashed or produced results from junk input"; fail=1
fi
rm -rf "$SARTMP"

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "SKIP: gitleaks not installed — secrets fixture assertions skipped (install: brew install gitleaks)"
  exit "$fail"
fi

EVAL="skills/secrets-scanner/scripts/eval_secrets.py"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

run_gitleaks() { # $1 subcommand, $2 report path, $3 repo — exit 0/1 are normal; >1 retried once, then loud
  local sub="$1" report="$2" repo="$3" rc=0
  gitleaks "$sub" --no-banner --redact --report-format json --report-path "$report" "$repo" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -gt 1 ]; then
    echo "WARN: gitleaks $sub exited $rc for $repo; retrying once"
    rc=0
    gitleaks "$sub" --no-banner --redact --report-format json --report-path "$report" "$repo" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -gt 1 ]; then
      echo "FAIL: gitleaks $sub errored twice (exit $rc) for $repo"
      fail=1
    fi
  fi
}

run_eval() { # $1 repo path -> writes $TMP/out.json; reports are always fresh (no stale reuse)
  local repo="$1"
  rm -f "$TMP/hist.json" "$TMP/dir.json" "$TMP/out.json"
  run_gitleaks git "$TMP/hist.json" "$repo"
  run_gitleaks dir "$TMP/dir.json" "$repo"
  python3 "$EVAL" --history-report "$TMP/hist.json" --dir-report "$TMP/dir.json" \
    --target "$repo" --gitleaks-version "test" --emit-json "$TMP/out.json"
}

assert() { # $1 description, $2 jq expression that must be true against $TMP/out.json
  if jq -e "$2" "$TMP/out.json" >/dev/null; then
    echo "OK: $1"
  else
    echo "FAIL: $1"
    echo "     (expression: $2)"
    fail=1
  fi
}

step "fixture secrets-generated: SS-01 history HIGH + SS-03 disk CRITICAL"
REPO="$(tests/fixtures/make-secrets-repo.sh | tail -1)"
run_eval "$REPO"
# gitleaks rule multiplicity on the same planted secret varies by random draw, so assert
# semantics (findings confined to planted files, correct check per file), not exact counts.
assert "findings confined to the two planted files" \
  '[.findings[].file] | unique | sort == [".env", "deploy-creds.txt"]'
assert "every deploy-creds.txt finding is history-only SS-01" \
  '[.findings[] | select(.file == "deploy-creds.txt") | .check_id] | (length > 0) and (unique == ["SS-01"])'
assert "SS-01 present, severity HIGH, history-only exposure" \
  '.findings | any(.check_id == "SS-01" and .severity == "HIGH" and .exposure.in_history and (.exposure.on_disk | not) and (.exposure.vcs_remote | not))'
assert "SS-03 present on .env, severity CRITICAL, confirmed, agent-readable" \
  '.findings | any(.check_id == "SS-03" and .file == ".env" and .severity == "CRITICAL" and .confidence == "confirmed" and .exposure.agent_readable)'
assert "no secret values leak into the report (no ghp_ or AKIA strings)" \
  '[tostring | test("ghp_[A-Za-z0-9]{36}|AKIA[A-Z0-9]{16}")] == [false]'
assert "every finding carries at least one citation" \
  '[.findings[] | .citations | length > 0] | all'
assert "every finding carries a fingerprint" \
  '[.findings[] | .fingerprint | length > 0] | all'

step "fixture secrets-generated-denied: deny rule flips SS-03 to SS-02 HIGH"
REPO="$(tests/fixtures/make-secrets-repo.sh --with-deny-rule | tail -1)"
run_eval "$REPO"
assert "SS-02 present on .env, severity HIGH, not agent-readable" \
  '.findings | any(.check_id == "SS-02" and .file == ".env" and .severity == "HIGH" and (.exposure.agent_readable | not))'
assert "no SS-03 finding (false-positive guard)" \
  '[.findings[] | select(.check_id == "SS-03")] | length == 0'

step "fixture secrets-generated-remote: pushed history flips SS-01 to SS-04 rotate-first"
REPO="$(tests/fixtures/make-secrets-repo.sh --with-remote | tail -1)"
run_eval "$REPO"
assert "SS-04 present with rotate_first and vcs_remote exposure" \
  '.findings | any(.check_id == "SS-04" and .rotate_first and .exposure.vcs_remote)'
assert "no SS-01 finding (exposure upgraded, not duplicated)" \
  '[.findings[] | select(.check_id == "SS-01")] | length == 0'

step "false-positive guard: clean repo yields zero findings"
CLEAN="$(dirname "$(tests/fixtures/make-secrets-repo.sh | tail -1)")/clean-repo"
rm -rf "$CLEAN" && mkdir -p "$CLEAN"
git -C "$CLEAN" init -q -b main
git -C "$CLEAN" -c user.name=fixture -c user.email=f@example.invalid commit -q --allow-empty -m "empty"
echo "README" > "$CLEAN/README.md"
run_eval "$CLEAN"
assert "clean repo: zero findings" '.findings | length == 0'

step "suppression: .ai-data-security-ignore moves a finding to the appendix"
REPO="$(tests/fixtures/make-secrets-repo.sh | tail -1)"
FP="$(run_eval "$REPO"; jq -r '[.findings[] | select(.check_id == "SS-03")][0].fingerprint' "$TMP/out.json")"
printf '%s reason=fixture test\n' "$FP" > "$REPO/.ai-data-security-ignore"
run_eval "$REPO"
assert "suppressed finding is in the appendix, not findings" \
  '(.findings | map(.check_id) | index("SS-03")) == null and (.suppressed | length == 1)'

PERMEVAL="skills/ai-config-audit/scripts/permeval.py"

step "fixture ai-config: AC-01..AC-05 findings + AC-06 unknown"
python3 "$PERMEVAL" --target tests/fixtures/ai-config \
  --home tests/fixtures/ai-config/home --emit-json "$TMP/out.json"
assert "AC-01: all 3 recommended deny rules reported missing" \
  '.findings | any(.check_id == "AC-01" and (.title | test("Missing 3")) and .severity == "HIGH")'
assert "AC-02: Bash(npx *) flagged as env-runner allow" \
  '.findings | any(.check_id == "AC-02" and (.title | test("npx")) and .severity == "HIGH")'
assert "AC-02: colon-wildcard spelling Bash(uvx:*) also flagged" \
  '.findings | any(.check_id == "AC-02" and (.title | test("uvx")))'
assert "AC-03: credential-shaped MCP env key flagged by name" \
  '.findings | any(.check_id == "AC-03" and (.evidence | test("WAREHOUSE_PASSWORD")))'
assert "AC-03: the placeholder value itself never appears in output" \
  '[tostring | test("placeholder-not-a-real-value")] == [false]'
assert "AC-04: gemini trust:true flagged" \
  '.findings | any(.check_id == "AC-04" and (.file | test("gemini")))'
assert "AC-05: transcript INFO present" \
  '.findings | any(.check_id == "AC-05" and .severity == "INFO")'
assert "AC-06: retention always reported UNKNOWN with manual-check action" \
  '.unknowns | any(.check_id == "AC-06" and (.action | test("data-privacy-controls")))'
assert "AC-07: sandbox not enabled in fixture home -> MEDIUM finding pointing at user settings" \
  '.findings | any(.check_id == "AC-07" and .severity == "MEDIUM" and (.remediation[0] | test("sandbox")))'
assert "every ai-config finding carries a citation and fingerprint" \
  '[.findings[] | (.citations | length > 0) and (.fingerprint | length > 0)] | all'

step "fixture ai-config-hardened: false-positive guard (any-depth deny spellings + sandbox on)"
python3 "$PERMEVAL" --target tests/fixtures/ai-config-hardened \
  --home tests/fixtures/ai-config-hardened/home --emit-json "$TMP/out.json"
assert "hardened config: zero findings (Read(.env) / **/ / //**/ spellings satisfy AC-01; sandbox on clears AC-07)" \
  '.findings | length == 0'
assert "hardened config: AC-06 unknown still present (never a clean bill)" \
  '.unknowns | any(.check_id == "AC-06")'

step "AC-07 default posture: a home with no sandbox setting is reported, not assumed safe"
EMPTYHOME="$TMP/empty-home"
mkdir -p "$EMPTYHOME"
python3 "$PERMEVAL" --target tests/fixtures/ai-config-hardened \
  --home "$EMPTYHOME" --emit-json "$TMP/out.json"
assert "empty home: exactly one finding and it is AC-07" \
  '(.findings | length == 1) and (.findings[0].check_id == "AC-07")'

step "AC-07 posture variants: filesystem.disabled re-fires MEDIUM; enabled without failIfUnavailable is INFO"
FSOFF="$TMP/fs-off-home"; mkdir -p "$FSOFF/.claude"
printf '{"sandbox": {"enabled": true, "filesystem": {"disabled": true}}}\n' > "$FSOFF/.claude/settings.json"
python3 "$PERMEVAL" --target tests/fixtures/ai-config-hardened --home "$FSOFF" --emit-json "$TMP/out.json"
assert "sandbox enabled but filesystem isolation disabled -> AC-07 MEDIUM" \
  '.findings | any(.check_id == "AC-07" and .severity == "MEDIUM" and (.evidence | test("filesystem.disabled")))'
SOFT="$TMP/soft-home"; mkdir -p "$SOFT/.claude"
printf '{"sandbox": {"enabled": true}}\n' > "$SOFT/.claude/settings.json"
python3 "$PERMEVAL" --target tests/fixtures/ai-config-hardened --home "$SOFT" --emit-json "$TMP/out.json"
assert "sandbox enabled without failIfUnavailable -> AC-07 INFO only" \
  '(.findings | map(select(.check_id == "AC-07")) | length == 1) and (.findings[] | select(.check_id == "AC-07") | .severity == "INFO")'

step "AC-01 spelling regression: the legacy ./ spelling still satisfies the rule (no false positive)"
LEGACY="$TMP/legacy-deny"
mkdir -p "$LEGACY/.claude"
printf '{"permissions": {"deny": ["Read(./.env)", "Read(./.env.*)", "Read(./secrets/**)"]}}\n' > "$LEGACY/.claude/settings.json"
python3 "$PERMEVAL" --target "$LEGACY" --home tests/fixtures/ai-config-hardened/home --emit-json "$TMP/out.json"
assert "legacy ./ spellings: no AC-01 finding" '[.findings[] | select(.check_id == "AC-01")] | length == 0'

CLASSIFY="skills/data-classification/scripts/classify_hints.py"

step "matcher unit tests (permission globs + fail-closed expiry)"
if ! python3 tests/test_matchers.py; then fail=1; fi

step "fixture classify-repo: deterministic floors, validators, no values in output"
python3 "$CLASSIFY" --target tests/fixtures/classify-repo --emit-json "$TMP/out.json"
assert "accounts.csv floors to Restricted, confirmed, via SSN + Luhn validators" \
  '.files | any(.path == "accounts.csv" and .floor == "Restricted" and .confidence == "confirmed" and .indicators.ssn_valid == 2 and .indicators.pan_luhn_valid >= 2)'
assert "customers.csv floors to Confidential via validated emails + PII columns" \
  '.files | any(.path == "customers.csv" and .floor == "Confidential" and .indicators.emails == 2 and (.pii_columns | length >= 2))'
assert "README.md and runbook.md floor to Internal (never auto-Public)" \
  '[.files[] | select(.path == "README.md" or .path == "runbook.md") | .floor == "Internal"] == [true, true]'
assert "no data values leak into hint output (no SSN/PAN/email strings)" \
  '[tostring | test("078-05-1120|4111111111111111|jane\\.doe@example\\.com")] == [false]'
assert "nothing is ever floored to Public" \
  '[.files[] | .floor != "Public"] | all'
assert "DC-01 finding emitted for accounts.csv (HIGH, confirmed, cited)" \
  '.findings | any(.check_id == "DC-01" and .file == "accounts.csv" and .severity == "HIGH" and .confidence == "confirmed" and (.citations | length > 0))'
assert "DC-02 finding emitted for customers.csv (MEDIUM)" \
  '.findings | any(.check_id == "DC-02" and .file == "customers.csv" and .severity == "MEDIUM")'

step "classification DC-03: unreadable file becomes an UNKNOWN, never a silent skip"
DCDIR="$TMP/dc-unreadable"
mkdir -p "$DCDIR"
echo "readable" > "$DCDIR/ok.txt"
echo "hidden" > "$DCDIR/locked.txt"
chmod 000 "$DCDIR/locked.txt"
if [ -r "$DCDIR/locked.txt" ]; then
  echo "SKIP: running as root (chmod 000 still readable) — DC-03 check skipped"
else
  python3 "$CLASSIFY" --target "$DCDIR" --emit-json "$TMP/out.json"
  assert "DC-03 unknown names the unreadable file" \
    '.unknowns | any(.check_id == "DC-03" and (.reason | test("locked.txt")))'
  assert "unreadable file absent from the classification table" \
    '[.files[] | .path] | index("locked.txt") == null'
fi
chmod 644 "$DCDIR/locked.txt" 2>/dev/null || true

step "classification suppression: .ai-data-security-ignore moves DC finding to appendix"
DCSUP="$TMP/dc-suppress"
mkdir -p "$DCSUP"
cp tests/fixtures/classify-repo/accounts.csv "$DCSUP/"
printf 'DC-01:accounts.csv:Restricted reason=fixture test\n' > "$DCSUP/.ai-data-security-ignore"
python3 "$CLASSIFY" --target "$DCSUP" --emit-json "$TMP/out.json"
assert "DC-01 suppressed into appendix" \
  '(.findings | map(.check_id) | index("DC-01")) == null and (.suppressed | length == 1)'

step "db-access-audit suppression via --ignore-dir (recorded CSVs, no docker)"
DBSUP="$TMP/db-suppress"
mkdir -p "$DBSUP"
printf 'DB-04:views:db reason=fixture test\n' > "$DBSUP/.ai-data-security-ignore"
python3 skills/db-access-audit/scripts/eval_grants.py \
  --grants tests/fixtures/postgres/expected/grants.csv \
  --pii tests/fixtures/postgres/expected/pii_columns.csv \
  --views tests/fixtures/postgres/expected/masked_views.csv \
  --settings tests/fixtures/postgres/expected/audit_logging.csv \
  --role ai_agent --principal-confirmed --ignore-dir "$DBSUP" --emit-json "$TMP/out.json"
assert "DB-04 suppressed into appendix; other findings intact" \
  '(.findings | map(.check_id) | index("DB-04")) == null and (.suppressed | length == 1) and (.findings | length >= 3)'

step "db-access-audit snowflake pack: script-computed verdicts match expected_findings.md"
python3 skills/db-access-audit/scripts/eval_grants.py --dialect snowflake \
  --grants tests/fixtures/snowflake/grants.txt --pii tests/fixtures/snowflake/pii_columns.txt \
  --views tests/fixtures/snowflake/masked_views.txt --settings tests/fixtures/snowflake/audit_logging.txt \
  --role AI_AGENT --principal-confirmed --emit-json "$TMP/out.json"
assert "DB-01 CRITICAL: INSERT/UPDATE on ANALYTICS.APP.CUSTOMERS" \
  '.findings | any(.check_id == "DB-01" and .severity == "CRITICAL" and (.evidence | test("ANALYTICS.APP.CUSTOMERS:INSERT")))'
assert "DB-02 HIGH: SELECT on base tables CUSTOMERS + ORDERS" \
  '.findings | any(.check_id == "DB-02" and .severity == "HIGH" and (.evidence | test("CUSTOMERS")) and (.evidence | test("ORDERS")))'
assert "DB-03 HIGH: Restricted SSN + CARD_NUMBER exposed" \
  '.findings | any(.check_id == "DB-03" and .severity == "HIGH" and (.evidence | test("SSN")) and (.evidence | test("CARD_NUMBER")))'
assert "DB-03 MEDIUM: Confidential EMAIL + FULL_NAME exposed" \
  '.findings | any(.check_id == "DB-03" and .severity == "MEDIUM" and (.evidence | test("EMAIL")) and (.evidence | test("FULL_NAME")))'
assert "DB-04: zero masking policies and zero views" '.findings | any(.check_id == "DB-04")'
assert "DB-05: probable at best (partly organizational)" \
  '.findings | any(.check_id == "DB-05" and .confidence == "probable" and .severity == "MEDIUM")'
assert "snowflake dialect recorded in tools" '.tools.dialect == "snowflake"'
python3 skills/db-access-audit/scripts/eval_grants.py --dialect snowflake \
  --grants tests/fixtures/snowflake/grants.txt --pii tests/fixtures/snowflake/pii_columns.txt \
  --views tests/fixtures/snowflake/masked_views.txt --settings tests/fixtures/snowflake/audit_logging.txt \
  --role AI_AGENT --emit-json "$TMP/out.json"
assert "unconfirmed principal: severities capped at MEDIUM + DB-06 says why" \
  '([.findings[] | .severity == "MEDIUM" or .severity == "LOW" or .severity == "INFO"] | all) and (.unknowns | any(.check_id == "DB-06"))'
printf -- '-- truncated garbage, no table\n' > "$TMP/garbage.txt"
python3 skills/db-access-audit/scripts/eval_grants.py --dialect snowflake \
  --grants "$TMP/garbage.txt" --pii tests/fixtures/snowflake/pii_columns.txt \
  --views tests/fixtures/snowflake/masked_views.txt --settings tests/fixtures/snowflake/audit_logging.txt \
  --role AI_AGENT --principal-confirmed --emit-json "$TMP/out.json"
assert "unparseable recorded output fails closed to DB-06 (no DB-01/DB-02 claimed)" \
  '(.unknowns | any(.check_id == "DB-06" and (.reason | test("grants")))) and ([.findings[] | .check_id] | index("DB-01") == null)'

step "org profile (.ai-data-security.yml): extends-only, fail-closed"
ORG="$TMP/org-repo"; mkdir -p "$ORG"
printf 'payoff_uid,widget\n1,2\n' > "$ORG/loan_tape_q2.csv"
printf 'member_ssn,customer_email,emailed_at\nx,y,z\n' > "$ORG/export.csv"
python3 skills/data-classification/scripts/classify_hints.py --target "$ORG" --emit-json "$TMP/out.json"
assert "token-boundary: member_ssn + customer_email caught, emailed_at not" \
  '(.files[] | select(.path == "export.csv") | .pii_columns) == ["member_ssn", "customer_email"]'
assert "without org profile, org-only names are not flagged" \
  '.files[] | select(.path == "loan_tape_q2.csv") | .pii_columns == []'
printf '{"classification": {"column_restricted": ["payoff_uid"], "filename_restricted": ["loan_tape"]}, "citations": [{"display": "Org Policy Fixture", "checks": ["DC-01"]}]}\n' > "$ORG/.ai-data-security.yml"
python3 skills/data-classification/scripts/classify_hints.py --target "$ORG" --emit-json "$TMP/out.json"
assert "org tokens raise the floor and appear in evidence" \
  '.files[] | select(.path == "loan_tape_q2.csv") | (.floor == "Restricted") and (.pii_columns | index("payoff_uid") != null)'
assert "org citation appended to matching findings only" \
  '[.findings[] | select(.check_id == "DC-01") | .citations | index("Org Policy Fixture") != null] | all and length > 0'
printf 'not json {{{\n' > "$ORG/.ai-data-security.yml"
python3 skills/data-classification/scripts/classify_hints.py --target "$ORG" --emit-json "$TMP/out.json"
assert "unparseable org profile -> DC-03 unknown, extensions not applied" \
  '(.unknowns | any(.check_id == "DC-03" and (.reason | test("org profile")))) and ((.files[] | select(.path == "loan_tape_q2.csv") | .floor) == "Internal")'

step "edge hardening: crash-resistance + value-leak regressions (from the bug hunt)"
CLASSIFY_S="skills/data-classification/scripts/classify_hints.py"
PERMEVAL_S="skills/ai-config-audit/scripts/permeval.py"
GRANTS_S="skills/db-access-audit/scripts/eval_grants.py"

# classify_hints: untraversable subdirectory -> DC-03 unknown, never a silent skip (blocker)
EH="$TMP/eh-walkerr"; mkdir -p "$EH/secretsub"
printf 'ssn,email\n123-45-6789,a@example.com\n' > "$EH/secretsub/hidden.csv"
printf 'id\n1\n' > "$EH/ok.csv"
chmod 000 "$EH/secretsub"
python3 "$CLASSIFY_S" --target "$EH" --emit-json "$TMP/out.json"
chmod 755 "$EH/secretsub"
assert "unreadable subdir emits a DC-03 unknown (fail-closed, not a silent skip)" \
  '.unknowns | any(.check_id == "DC-03" and (.reason | test("secretsub")))'

# classify_hints: no raw field text leaks into pii_columns / evidence (blocker: value leak)
EH2="$TMP/eh-leak"; mkdir -p "$EH2"
printf 'row_id,medical note: patient Jane Q Public HIV+ policy#A1234567\n1,ok\n' > "$EH2/dump.csv"
python3 "$CLASSIFY_S" --target "$EH2" --emit-json "$TMP/out.json"
assert "free-text header field never captured as a column (no value leak)" \
  '[tostring | test("Jane Q Public|HIV")] == [false]'

# classify_hints: FIFO does not hang the scan (bounded by a short timeout here)
EH3="$TMP/eh-fifo"; mkdir -p "$EH3"; mkfifo "$EH3/pipe" 2>/dev/null || true
if [ -p "$EH3/pipe" ]; then
  if run_bounded 15 python3 "$CLASSIFY_S" --target "$EH3" --emit-json "$TMP/out.json"; then
    assert "FIFO surfaced as DC-03, scan did not hang" '.unknowns | any(.check_id == "DC-03")'
  else
    echo "FAIL: classify_hints hung or errored on a FIFO (exit $?)"; fail=1
  fi
fi

# classify_hints: BOM UTF-16 text with a valid SSN is scanned, not filed Internal-binary
EH4="$TMP/eh-utf16"; mkdir -p "$EH4"
python3 - "$EH4/wide.txt" <<'PY'
import sys
open(sys.argv[1], "wb").write("account\nssn 078-05-1120\n".encode("utf-16"))
PY
python3 "$CLASSIFY_S" --target "$EH4" --emit-json "$TMP/out.json"
assert "UTF-16 file with a valid SSN yields a Restricted DC-01 (not silent Internal)" \
  '.findings | any(.check_id == "DC-01" and (.file | test("wide.txt")))'

# permeval: malformed / hostile config shapes must not crash the audit (fail-open -> crash)
EHP="$TMP/eh-perm"; mkdir -p "$EHP/.claude"
printf '{"permissions": null}\n' > "$EHP/.claude/settings.json"
printf '{"mcpServers": {"s": {"command": "x", "env": null}}}\n' > "$EHP/.mcp.json"
mkdir -p "$EHP/.cursor"; printf '["not-an-object"]\n' > "$EHP/.cursor/mcp.json"
EHHOME="$TMP/eh-perm-home"; mkdir -p "$EHHOME/.codex"
mkdir -p "$EHHOME/.codex/config.toml"  # a DIRECTORY where a file is expected
if python3 "$PERMEVAL_S" --target "$EHP" --home "$EHHOME" --emit-json "$TMP/out.json" 2>"$TMP/err"; then
  assert "hostile configs still yield a well-formed run with the AC-06 unknown" \
    '.unknowns | any(.check_id == "AC-06")'
  assert "permissions:null still produces the AC-01 finding (did not crash out)" \
    '.findings | any(.check_id == "AC-01")'
else
  echo "FAIL: permeval crashed on hostile config shapes:"; cat "$TMP/err"; fail=1
fi

# eval_grants: a present-but-malformed CSV fails closed to DB-06, does not KeyError-crash
EHG="$TMP/eh-grants"; mkdir -p "$EHG/expected"
printf 'wrong,header\na,b\n' > "$EHG/grants.csv"
cp tests/fixtures/postgres/expected/pii_columns.csv "$EHG/pii.csv"
cp tests/fixtures/postgres/expected/masked_views.csv "$EHG/views.csv"
cp tests/fixtures/postgres/expected/audit_logging.csv "$EHG/settings.csv"
if python3 "$GRANTS_S" --grants "$EHG/grants.csv" --pii "$EHG/pii.csv" \
     --views "$EHG/views.csv" --settings "$EHG/settings.csv" \
     --role ai_agent --principal-confirmed --emit-json "$TMP/out.json" 2>"$TMP/err"; then
  assert "malformed grants.csv -> DB-06 unknown (fail closed, no crash)" \
    '.unknowns | any(.check_id == "DB-06" and (.reason | test("grants")))'
else
  echo "FAIL: eval_grants crashed on a malformed CSV:"; cat "$TMP/err"; fail=1
fi

step "doctor: capability matrix, registry health, always exits 0"
python3 skills/doctor/scripts/doctor.py --home tests/fixtures/ai-config/home --format json --emit-json "$TMP/out.json" >/dev/null
assert "doctor: registry healthy and every evaluator compiles" \
  '.registry.ok and ([.evaluators[]] | all(. == "ok"))'
assert "doctor: gitleaks detected and secrets-scanner marked ready (gitleaks is installed in this run)" \
  '.tools.gitleaks.present and (.capabilities | any(.skill == "secrets-scanner" and .status == "ready"))'
assert "doctor: fixture home without sandbox reported, AC-06 listed as always unknown" \
  '(.sandbox.sandbox_enabled | not) and (.always_unknown | index("AC-06") != null)'
assert "doctor: betterleaks row is information-only" '.tools.betterleaks.info_only'
if ! python3 skills/doctor/scripts/doctor.py --home "$TMP/nonexistent-home" >/dev/null; then
  echo "FAIL: doctor must exit 0 even with a missing home"; fail=1
else
  echo "OK: doctor exits 0 with a missing home"
fi

step "quick-check: three verdict lines over the combined fixture, under 120s, findings pass through"
COMBINED="$(tests/fixtures/make-combined-repo.sh | tail -1)"
QC_START=$(date +%s)
python3 skills/quick-check/scripts/quick_check.py --target "$COMBINED" \
  --home tests/fixtures/ai-config/home --emit-json "$TMP/out.json" > "$TMP/qc.txt"
QC_ELAPSED=$(( $(date +%s) - QC_START ))
assert "quick-check: exactly three verdict lines" '.verdicts | length == 3'
assert "quick-check: SS-03 (agent-readable .env), AC-01, AC-07, DC-01 all pass through with citations" \
  '[.findings[] | select(.citations | length > 0) | .check_id] | (index("SS-03") != null and index("AC-01") != null and index("AC-07") != null and index("DC-01") != null)'
assert "quick-check: unknowns include SS-01 (history not scanned), AC-06, DB-06 (no warehouse)" \
  '[.unknowns[].check_id] | (index("SS-01") != null and index("AC-06") != null and index("DB-06") != null)'
assert "quick-check: every finding is labelled with its skill" '[.findings[] | .skill | length > 0] | all'
assert "quick-check: no secret values in the merged JSON" \
  '[tostring | test("ghp_[A-Za-z0-9]{36}|AKIA[A-Z0-9]{16}")] == [false]'
if [ "$(grep -c '^[123]\. ' "$TMP/qc.txt")" -eq 3 ]; then
  echo "OK: quick-check text output prints exactly three numbered verdict lines"
else
  echo "FAIL: quick-check text output did not print three numbered verdict lines"; fail=1
fi
if [ "$QC_ELAPSED" -lt 120 ]; then
  echo "OK: quick-check finished in ${QC_ELAPSED}s (< 120s)"
else
  echo "FAIL: quick-check took ${QC_ELAPSED}s (>= 120s)"; fail=1
fi

step "quick-check: a suppressed AC-01 is reported as suppressed, never as 'deny rules present'"
python3 skills/quick-check/scripts/quick_check.py --target "$COMBINED" --home tests/fixtures/ai-config/home --emit-json "$TMP/qc0.json" >/dev/null
AC01FP="$(jq -r '[.findings[] | select(.check_id == "AC-01")][0].fingerprint' "$TMP/qc0.json")"
printf '%s reason=fixture\n' "$AC01FP" > "$COMBINED/.ai-data-security-ignore"
python3 skills/quick-check/scripts/quick_check.py --target "$COMBINED" --home tests/fixtures/ai-config/home --emit-json "$TMP/out.json" >/dev/null
rm -f "$COMBINED/.ai-data-security-ignore"
assert "quick-check: verdict line 2 says the deny-rule finding is suppressed" \
  '.verdicts[1] | test("deny-rule finding suppressed") and (test("deny rules present") | not)'
assert "quick-check: SS-01 (history not scanned) is listed even when the secrets lane ran" \
  '.unknowns | any(.check_id == "SS-01")'
cp "$TMP/qc0.json" "$TMP/out.json"

step "SARIF export: valid 2.1.0 shape, one rule per check, unknowns as notifications, no values"
python3 scripts/to_sarif.py "$TMP/out.json" -o "$TMP/out.sarif"
cp "$TMP/out.sarif" "$TMP/out.json"
assert "sarif: version 2.1.0 with a single run and a named driver" \
  '.version == "2.1.0" and (.runs | length == 1) and .runs[0].tool.driver.name == "ai-data-security"'
assert "sarif: every result references a declared rule" \
  '([.runs[0].results[].ruleId] - [.runs[0].tool.driver.rules[].id]) == []'
assert "sarif: CRITICAL/HIGH map to error, MEDIUM to warning, INFO to note" \
  'all(.runs[0].results[]; ((.properties.severity | IN("CRITICAL","HIGH")) == (.level == "error")) and ((.properties.severity == "MEDIUM") == (.level == "warning")) and ((.properties.severity | IN("INFO","LOW")) == (.level == "note")))'
assert "sarif: unknowns became tool notifications" \
  '.runs[0].invocations[0].toolExecutionNotifications | length >= 3'
assert "sarif: every result carries the ai-data-security fingerprint" \
  '[.runs[0].results[] | .partialFingerprints["ai-data-security/v1"] | length > 0] | all'
assert "sarif: no secret values" '[tostring | test("ghp_[A-Za-z0-9]{36}|AKIA[A-Z0-9]{16}")] == [false]'

step "postgres pack (docker; self-skips when unavailable)"
if ! tests/postgres-fixture-check.sh; then
  echo "FAIL: postgres pack checks"
  fail=1
fi

echo
if [ "$fail" -eq 0 ]; then echo "FIXTURES: PASS"; else echo "FIXTURES: FAIL"; exit 1; fi
