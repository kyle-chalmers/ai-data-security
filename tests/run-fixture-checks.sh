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
assert "AC-03 via a v0.5 path: VS Code .vscode/mcp.json servers header key flagged by name, value never shown" \
  '(.findings | any(.check_id == "AC-03" and (.file == ".vscode/mcp.json") and (.evidence | test("headers.Authorization")))) and ([tostring | test("placeholder-not-a-real-value")] == [false])'
assert "AC-08 INFO: warehouse servers + remote MCP compose; named as inventory, not detection" \
  '.findings | any(.check_id == "AC-08" and .severity == "INFO" and (.evidence | test("snowflake")) and (.evidence | test("remote MCP")) and (.evidence | test("not a detection")))'
assert "AC-09 MEDIUM/probable: npx -y unpinned (.mcp.json), uvx unpinned, Continue mcpServers/*.yaml npx; pinned pipx run pkg==x.y.z and OpenCode @2.0.0 are not flagged" \
  '([.findings[] | select(.check_id == "AC-09")] | length == 3) and ([.findings[] | select(.check_id == "AC-09") | .confidence == "probable"] | all) and (.findings | any(.check_id == "AC-09" and (.file | test("continue/mcpServers")))) and ([.findings[] | select(.check_id == "AC-09" and ((.evidence | test("lineage")) or (.evidence | test("bi-mcp"))))] | length == 0)'
assert "AC-03 via OpenCode mcp.servers nesting: BI_API_KEY flagged by key name" \
  '.findings | any(.check_id == "AC-03" and (.file == "opencode.json") and (.evidence | test("BI_API_KEY")))'
assert "AC-10 HIGH x3: Snowflake sql_statement_permissions (Insert/Delete/Command), Postgres unrestricted, Toolbox DELETE tool" \
  '([.findings[] | select(.check_id == "AC-10" and .severity == "HIGH")] | length == 3) and (.findings | any(.check_id == "AC-10" and (.evidence | test("Command, Delete, Insert, Unknown")))) and (.findings | any(.check_id == "AC-10" and (.evidence | test("unrestricted")))) and (.findings | any(.check_id == "AC-10" and (.evidence | test("archive-rows, purge-test-rows")) and (.evidence | test("weekly-summary") | not) and (.evidence | test("DELETE") | not)))'
assert "AC-10 UNKNOWNs: remote Postgres MCP (access mode not local) and one unclassifiable Toolbox statement (set-path)" \
  '([.unknowns[] | select(.check_id == "AC-10")] | length == 2) and (.unknowns | any(.check_id == "AC-10" and (.reason | test("postgres-mcp-remote")) and (.reason | test("remote")))) and (.unknowns | any(.check_id == "AC-10" and (.reason | test("set-path"))))'
assert "AC-11: DuckDB persistent secret (HIGH), Snowflake connections.toml password key (HIGH, key name only), shell history (LOW)" \
  '(.findings | any(.check_id == "AC-11" and .severity == "HIGH" and (.title | test("DuckDB")))) and (.findings | any(.check_id == "AC-11" and .severity == "HIGH" and (.evidence | test("password")) and (.evidence | test("example-account") | not))) and (.findings | any(.check_id == "AC-11" and .severity == "LOW" and (.title | test("history"))))'
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

step "AC-10 fail-closed: missing / hostile Snowflake service config -> UNKNOWN, never a pass"
BADMCP="$TMP/badmcp"; mkdir -p "$BADMCP/.claude" "$BADMCP/mcp"
printf '{"mcpServers": {"snowflake": {"command": "uvx", "args": ["snowflake-labs-mcp@1.2.3", "--service-config-file", "./mcp/missing.yaml"]}, "sf2": {"command": "uvx", "args": ["snowflake-labs-mcp@1.2.3", "--service-config-file", "./mcp/hostile.yaml"]}}}\n' > "$BADMCP/.mcp.json"
printf 'sql_statement_permissions: &anchor\n  - Insert: True\n\t- weird: [unterminated\n' > "$BADMCP/mcp/hostile.yaml"
python3 "$PERMEVAL" --target "$BADMCP" --home tests/fixtures/ai-config-hardened/home --emit-json "$TMP/out.json"
assert "missing and unparseable Snowflake configs -> two AC-10 unknowns, zero AC-10 findings, pinned packages -> no AC-09" \
  '([.unknowns[] | select(.check_id == "AC-10")] | length == 2) and ([.findings[] | select(.check_id == "AC-10" or .check_id == "AC-09")] | length == 0)'

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

step "fixture classify-validators: phone / IBAN / IPv4 validators (v0.5), no values in output"
python3 "$CLASSIFY" --target tests/fixtures/classify-validators --emit-json "$TMP/out.json"
assert "contacts.csv floors to Restricted via 2 mod-97-valid IBANs, confirmed; 2 phones, 2 IPv4" \
  '.files | any(.path == "contacts.csv" and .floor == "Restricted" and .confidence == "confirmed" and .indicators.iban_valid == 2 and .indicators.phones == 2 and .indicators.ipv4_valid == 2)'
assert "validator evidence names counts only; no IBAN, phone, or IP value appears" \
  '(.findings | any(.check_id == "DC-01" and (.evidence | test("mod-97")))) and ([tostring | test("GB82WEST|4155550100|203\\.0\\.113")] == [false])'

DBT="skills/dbt-governance-audit/scripts/dbt_audit.py"
step "fixture dbt-project: DBT-01 exposures on tagged models, DBT-02 untagged PII columns, DBT-03 UNKNOWN on bad YAML, DBT-04 INFO"
python3 "$DBT" --target tests/fixtures/dbt-project --emit-json "$TMP/out.json"
assert "DBT-01 fires for both exposures (application + dashboard) consuming PII-tagged models via versioned / package-qualified refs; MEDIUM/probable" \
  '([.findings[] | select(.check_id == "DBT-01")] | length == 2) and (.findings | any(.check_id == "DBT-01" and (.title | test("ai_agent_semantic_layer")) and .severity == "MEDIUM" and .confidence == "probable" and (.evidence | test("customer_360")) and (.evidence | test("customer_masked") | not)))'
assert "explicit meta masking is honored per model; a 'curated' name is only a hint (summary reports both)" \
  '(.summary.masking_declared_nodes == ["customer_masked"]) and (.summary.masked_name_hints | index("customer_curated")) != null'
assert "flow-map meta ({contains_pii: true}) and a block-scalar description parse; customer_360 is tagged" \
  '.summary.pii_tagged_nodes | index("customer_360") != null'
assert "DBT-02 names customers.ssn (Restricted) and stg_customers.phone_number (Confidential); emailed_at is not matched" \
  '(.findings | any(.check_id == "DBT-02" and (.evidence | test("customers\\.ssn")) and (.evidence | test("phone_number")) and (.evidence | test("emailed_at") | not)))'
assert "every DBT finding repeats that a missing tag is not proof of no PII (or is the INFO inventory)" \
  '[.findings[] | select(.check_id != "DBT-04") | .evidence | test("not proof of no PII")] | all'
assert "broken.yml -> one DBT-03 UNKNOWN naming the file; no finding derived from it" \
  '([.unknowns[] | select(.check_id == "DBT-03" and (.reason | test("broken\\.yml")))] | length == 1) and ([.findings[] | select(.file | test("broken"))] | length == 0)'
assert "unparseable depends_on (ref(var(...))) -> DBT-03 UNKNOWN naming the exposure, not a silent skip" \
  '.unknowns | any(.check_id == "DBT-03" and (.reason | test("legacy_report")))'
assert "DBT-04 INFO: no masking package declared" \
  '.findings | any(.check_id == "DBT-04" and .severity == "INFO" and (.title | test("No masking package")))'
assert "summary lists tagged nodes and exposures; no column data values exist to leak (declarations only)" \
  '(.summary.pii_tagged_nodes | index("customer_360")) != null and (.summary.exposures | length == 3)'
DBTMISS="$TMP/dbtmiss"; mkdir -p "$DBTMISS"
python3 "$DBT" --target "$DBTMISS" --emit-json "$TMP/out.json"
assert "no dbt_project.yml -> DBT-03 UNKNOWN, zero findings (fail closed, not a clean report)" \
  '(.findings | length == 0) and ([.unknowns[] | select(.check_id == "DBT-03")] | length == 1)'

PLAN="skills/safe-db-access/scripts/plan.py"
step "planner (v0.6): byte-stable renders for both dialects, refusal paths, sections sum to the whole"
E=tests/fixtures/postgres/expected; S=tests/fixtures/snowflake
python3 skills/db-access-audit/scripts/eval_grants.py --dialect postgres --grants $E/grants.csv --pii $E/pii_columns.csv \
  --views $E/masked_views.csv --settings $E/audit_logging.csv --identity $E/identity.csv --policies $E/policy_attachment.csv \
  --external $E/external_paths.csv --audit-quality $E/audit_quality.csv --columns $E/columns.csv \
  --role ai_agent --principal-confirmed --ignore-dir tests/fixtures/postgres --emit-json "$TMP/pg.json"
python3 skills/db-access-audit/scripts/eval_grants.py --dialect snowflake --grants $S/grants.txt --pii $S/pii_columns.txt \
  --views $S/masked_views.txt --settings $S/audit_logging.txt --identity $S/identity.txt --policies $S/policy_references.txt \
  --audit-quality $S/audit_quality.txt --role AI_AGENT --principal-confirmed --ignore-dir $S --emit-json "$TMP/sf.json"
python3 "$PLAN" --audit "$TMP/pg.json" > "$TMP/pg.plan.sql"
python3 "$PLAN" --audit "$TMP/sf.json" --edition enterprise > "$TMP/sf.plan.sql"
if diff -u tests/fixtures/planner/postgres.plan.sql "$TMP/pg.plan.sql"; then echo "OK: postgres plan matches golden"; else echo "FAIL: postgres plan diverges from golden"; fail=1; fi
if diff -u tests/fixtures/planner/snowflake.plan.sql "$TMP/sf.plan.sql"; then echo "OK: snowflake plan matches golden"; else echo "FAIL: snowflake plan diverges from golden"; fail=1; fi
for d in pg sf; do
  : > "$TMP/$d.sections.sql"
  for sec in header identity vault curated grants audit validate rollback; do
    args=(); [ "$d" = sf ] && args=(--edition enterprise)
    python3 "$PLAN" --audit "$TMP/$d.json" --section "$sec" "${args[@]}" >> "$TMP/$d.sections.sql"
  done
  if cmp -s "$TMP/$d.plan.sql" "$TMP/$d.sections.sql"; then echo "OK: $d sections concatenate to the whole plan"; else echo "FAIL: $d --section output differs from the whole"; fail=1; fi
done
if grep -q '{{' "$TMP/pg.plan.sql" "$TMP/sf.plan.sql"; then echo "FAIL: unfilled slot in a plan"; fail=1; else echo "OK: no unfilled template slots"; fi
if grep -qiE "fixture-placeholder|password *=|PASSWORD '" "$TMP/pg.plan.sql" "$TMP/sf.plan.sql"; then echo "FAIL: credential-like text in a plan"; fail=1; else echo "OK: plans carry no credential text"; fi
if grep -q 'PSEUDONYMIZED personal' "$TMP/pg.plan.sql" && grep -q 'PSEUDONYMIZED personal' "$TMP/sf.plan.sql"; then echo "OK: both plans state pseudonymized-not-anonymized"; else echo "FAIL: pseudonymization statement missing"; fail=1; fi
# refusals: nothing rendered, non-zero exit
if out="$(python3 "$PLAN" --audit "$TMP/pg.json" --curated-schema 'cur;DROP' 2>/dev/null)"; then echo "FAIL: hostile --curated-schema accepted"; fail=1; elif [ -n "$out" ]; then echo "FAIL: refusal still printed a plan"; fail=1; else echo "OK: hostile --curated-schema refused with empty stdout"; fi
if out="$(python3 "$PLAN" --audit "$TMP/pg.json" --ai-role '"ai_agent"' 2>/dev/null)"; then echo "FAIL: quoted --ai-role accepted"; fail=1; elif [ -n "$out" ]; then echo "FAIL: refusal printed a plan"; fail=1; else echo "OK: quoted --ai-role refused"; fi
if out="$(python3 "$PLAN" --audit "$TMP/pg.json" --curated-schema same --vault-schema same 2>/dev/null)"; then echo "FAIL: curated == vault accepted"; fail=1; else echo "OK: curated == vault refused"; fi
jq 'del(.plan_inputs)' "$TMP/pg.json" > "$TMP/pg-noplan.json"
if out="$(python3 "$PLAN" --audit "$TMP/pg-noplan.json" 2>/dev/null)"; then echo "FAIL: audit without plan_inputs accepted"; fail=1; else echo "OK: audit JSON without plan_inputs refused"; fi
# hostile object name from the warehouse: excluded and listed, never rendered
jq '.plan_inputs.raw_tables += [{"schema":"app","table":"evil; DROP TABLE x--"}] | .plan_inputs.pii_columns += [{"schema":"app","table":"customers","column":"x\") OR 1=1--","tier":"Restricted"}]' "$TMP/pg.json" > "$TMP/pg-hostile.json"
python3 "$PLAN" --audit "$TMP/pg-hostile.json" > "$TMP/pg-hostile.plan.sql"
if grep -q 'DROP TABLE x' "$TMP/pg-hostile.plan.sql" || grep -q 'OR 1=1' "$TMP/pg-hostile.plan.sql"; then echo "FAIL: hostile identifier reached the plan"; fail=1; else echo "OK: hostile identifiers never reach the plan text"; fi
if grep -q "NOT RENDERED" "$TMP/pg-hostile.plan.sql" && [ "$(grep -c '<refused:' "$TMP/pg-hostile.plan.sql")" -eq 2 ] && ! grep -q 'evil' "$TMP/pg-hostile.plan.sql"; then echo "OK: hostile identifiers listed under NOT RENDERED by hash handle only"; else echo "FAIL: hostile identifiers not reported (or echoed)"; fail=1; fi
# Codex gate v0.6: namespace/role collisions refused; hostile check_id never echoed; basename collisions; PUBLIC gated; provenance-based pseudonymization
if out="$(python3 "$PLAN" --audit "$TMP/pg.json" --vault-schema app 2>/dev/null)"; then echo "FAIL: --vault-schema equal to a raw schema accepted (rollback would DROP it)"; fail=1; else echo "OK: vault schema colliding with a raw schema refused"; fi
if out="$(python3 "$PLAN" --audit "$TMP/pg.json" --curated-schema public 2>/dev/null)"; then echo "FAIL: reserved schema accepted"; fail=1; else echo "OK: reserved schema refused"; fi
if out="$(python3 "$PLAN" --audit "$TMP/pg.json" --owner-role ai_agent 2>/dev/null)"; then echo "FAIL: owner role == AI role accepted"; fail=1; else echo "OK: owner role == AI role refused"; fi
if out="$(python3 "$PLAN" --audit "$TMP/sf.json" --auditor-role AI_AGENT 2>/dev/null)"; then echo "FAIL: auditor role == AI role accepted"; fail=1; else echo "OK: auditor role == AI role refused"; fi
jq '.findings += [{"check_id": "DB-99\nDROP TABLE app.customers; --", "severity": "INFO"}]' "$TMP/pg.json" > "$TMP/pg-checkid.json"
python3 "$PLAN" --audit "$TMP/pg-checkid.json" > "$TMP/pg-checkid.plan.sql"
if grep -q 'DROP TABLE app.customers' "$TMP/pg-checkid.plan.sql"; then echo "FAIL: hostile check_id reached the plan header"; fail=1; else echo "OK: hostile check_id dropped from the header"; fi
jq '.plan_inputs.raw_tables += [{"schema":"support","table":"customers"}]' "$TMP/pg.json" > "$TMP/pg-dup.json"
python3 "$PLAN" --audit "$TMP/pg-dup.json" > "$TMP/pg-dup.plan.sql"
if grep -q 'VIEW curated.app_customers AS' "$TMP/pg-dup.plan.sql" && grep -q 'VIEW curated.support_customers AS' "$TMP/pg-dup.plan.sql" && ! grep -q 'VIEW curated.customers AS' "$TMP/pg-dup.plan.sql"; then echo "OK: duplicate basenames get schema-qualified view names"; else echo "FAIL: duplicate basenames collide"; fail=1; fi
if grep -q '^-- REVIEW, then remove this comment marker to run: REVOKE SELECT ON app.orders FROM PUBLIC;' "$TMP/pg.plan.sql" && ! grep -q '^REVOKE SELECT ON app.orders FROM PUBLIC;' "$TMP/pg.plan.sql"; then echo "OK: PUBLIC revocation rendered commented out by default, exact privilege"; else echo "FAIL: PUBLIC revocation not gated"; fail=1; fi
python3 "$PLAN" --audit "$TMP/pg.json" --include-public-revokes > "$TMP/pg-public.plan.sql"
if grep -q '^REVOKE SELECT ON app.orders FROM PUBLIC;' "$TMP/pg-public.plan.sql" && grep -q '^GRANT SELECT ON app.orders TO PUBLIC;' "$TMP/pg-public.plan.sql"; then echo "OK: --include-public-revokes renders exact revoke and exact rollback"; else echo "FAIL: --include-public-revokes"; fail=1; fi
if grep -q 'ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA app REVOKE ALL ON TABLES FROM ai_agent;' "$TMP/pg.plan.sql"; then echo "OK: default privileges revoked FOR ROLE the captured grantor"; else echo "FAIL: default privileges missing FOR ROLE"; fail=1; fi
jq '.plan_inputs.pii_columns += [{"schema":"APP","table":"CUSTOMERS","column":"DOB","tier":"Restricted","type":"DATE"}]' "$TMP/sf.json" > "$TMP/sf-date.json"
python3 "$PLAN" --audit "$TMP/sf-date.json" --edition enterprise > "$TMP/sf-date.plan.sql"
if grep -q 'Status: INCOMPLETE' "$TMP/sf-date.plan.sql" && grep -q 'DOB is DATE' "$TMP/sf-date.plan.sql" && ! grep -q 'MODIFY COLUMN DOB SET MASKING POLICY' "$TMP/sf-date.plan.sql"; then echo "OK: non-STRING Restricted column gets no STRING policy; plan INCOMPLETE"; else echo "FAIL: type-mismatched policy attach"; fail=1; fi
# provenance: a BASE-TABLE column named ssn_hash stays Restricted (names are not evidence)
python3 - "$E" "$TMP" <<'PY'
import csv, sys, shutil, os
e, tmp = sys.argv[1], sys.argv[2]
d = os.path.join(tmp, "pg-hashname"); os.makedirs(d, exist_ok=True)
for f in os.listdir(e): shutil.copy(os.path.join(e, f), d)
with open(os.path.join(d, "pii_columns.csv"), "a", newline="") as fh:
    csv.writer(fh).writerow(["app", "customers", "ssn_hash", "text", "Restricted"])
PY
H="$TMP/pg-hashname"
python3 skills/db-access-audit/scripts/eval_grants.py --dialect postgres --grants "$H/grants.csv" --pii "$H/pii_columns.csv" --views "$H/masked_views.csv" --settings "$H/audit_logging.csv" --identity "$H/identity.csv" --policies "$H/policy_attachment.csv" --external "$H/external_paths.csv" --audit-quality "$H/audit_quality.csv" --columns "$H/columns.csv" --role ai_agent --principal-confirmed --emit-json "$TMP/pg-hashname.json"
if jq -e '.findings | any(.check_id == "DB-03" and .severity == "HIGH" and (.evidence | test("ssn_hash")))' "$TMP/pg-hashname.json" >/dev/null && jq -e '[.findings[] | select(.check_id == "DB-03" and .severity == "INFO")] | length == 0' "$TMP/pg-hashname.json" >/dev/null && jq -e '.plan_inputs.pii_columns | any(.column == "ssn_hash" and .tier == "Restricted")' "$TMP/pg-hashname.json" >/dev/null; then echo "OK: base-table ssn_hash stays Restricted (no pseudonymized downgrade by name)"; else echo "FAIL: name-only pseudonymization downgrade"; fail=1; fi
# missing columns input -> INCOMPLETE, view body not rendered
jq '.plan_inputs.columns = null' "$TMP/pg.json" > "$TMP/pg-nocols.json"
python3 "$PLAN" --audit "$TMP/pg-nocols.json" > "$TMP/pg-nocols.plan.sql"
if grep -q 'Status: INCOMPLETE' "$TMP/pg-nocols.plan.sql" && grep -q 'INCOMPLETE: app.customers' "$TMP/pg-nocols.plan.sql" && ! grep -q 'hash_pii(email' "$TMP/pg-nocols.plan.sql"; then echo "OK: missing columns -> INCOMPLETE, PII view not rendered"; else echo "FAIL: missing columns did not fail closed"; fail=1; fi

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

step "db-access-audit postgres recorded CSVs: v0.4 checks from goldens (no docker)"
PGE="tests/fixtures/postgres/expected"
python3 skills/db-access-audit/scripts/eval_grants.py \
  --grants "$PGE/grants.csv" --pii "$PGE/pii_columns.csv" --views "$PGE/masked_views.csv" \
  --settings "$PGE/audit_logging.csv" --identity "$PGE/identity.csv" --policies "$PGE/policy_attachment.csv" \
  --external "$PGE/external_paths.csv" --audit-quality "$PGE/audit_quality.csv" \
  --role ai_agent --principal-confirmed --emit-json "$TMP/out.json"
assert "pg goldens: DB-ID-01, DB-07, DB-08, DB-09, DB-10 all fire" \
  '[.findings[].check_id] | (index("DB-ID-01") != null and index("DB-07") != null and index("DB-08") != null and index("DB-09") != null and index("DB-10") != null)'
assert "pg goldens: DB-10 is CRITICAL for pg_write_server_files" \
  '.findings | any(.check_id == "DB-10" and .severity == "CRITICAL")'
python3 skills/db-access-audit/scripts/eval_grants.py \
  --grants "$PGE/grants.csv" --pii "$PGE/pii_columns.csv" --views "$PGE/masked_views.csv" \
  --settings "$PGE/audit_logging.csv" --role ai_agent --principal-confirmed --emit-json "$TMP/out.json"
assert "pg without v0.4 inputs: four DB-06 'not captured' unknowns, none of the five v0.4 findings claimed" \
  '([.unknowns[] | select(.reason | test("not captured"))] | length == 4) and ([.findings[].check_id] | (index("DB-ID-01") == null and index("DB-07") == null and index("DB-08") == null and index("DB-09") == null and index("DB-10") == null))'
python3 skills/db-access-audit/scripts/eval_grants.py \
  --grants "$PGE/grants.csv" --pii "$TMP/does-not-exist.csv" --views "$PGE/masked_views.csv" \
  --settings "$PGE/audit_logging.csv" --identity "$PGE/identity.csv" --policies "$PGE/policy_attachment.csv" \
  --external "$PGE/external_paths.csv" --audit-quality "$PGE/audit_quality.csv" \
  --role ai_agent --principal-confirmed --emit-json "$TMP/out.json"
assert "pg with pii_columns missing: DB-07 not claimed; DB-06 says DB-07 was not assessed" \
  '([.findings[].check_id] | index("DB-07") == null) and (.unknowns | any(.reason | test("DB-07")))'

step "db-access-audit databricks pack (v0.7): recorded Unity Catalog CSVs -> module verdicts"
DBX="tests/fixtures/databricks"
python3 skills/db-access-audit/scripts/eval_grants.py --dialect databricks --recorded "$DBX" \
  --role ai-agent@example.invalid --principal-confirmed --ignore-dir "$DBX" --emit-json "$TMP/out.json"
assert "DB-01 CRITICAL: direct MODIFY on app.customers and ownership of the external table app.orders" \
  '.findings | any(.check_id == "DB-01" and .severity == "CRITICAL" and (.evidence | test("app.customers:MODIFY \\(direct\\)")) and (.evidence | test("Owns 1 securable\\(s\\): TABLE app.orders")))'
assert "DB-02 HIGH: base tables read directly and via the analysts group's schema-level SELECT (inherited_from named)" \
  '.findings | any(.check_id == "DB-02" and .severity == "HIGH" and (.evidence | test("app.customers \\(direct\\)")) and (.evidence | test("via group analysts, inherited from analytics.app")) and (.evidence | test("CATALOG analytics \\(via group all-data-readers\\)")))'
assert "DB-03: Restricted (ssn, card_number) HIGH and Confidential (email, full_name) MEDIUM; names only" \
  '(.findings | any(.check_id == "DB-03" and .severity == "HIGH" and (.evidence | test("ssn")) and (.evidence | test("card_number")))) and (.findings | any(.check_id == "DB-03" and .severity == "MEDIUM" and (.evidence | test("email"))))'
assert "DB-04 MEDIUM: no views, no column masks" '.findings | any(.check_id == "DB-04" and .severity == "MEDIUM")'
assert "DB-05 MEDIUM/probable: system.access exists but nobody but admins can read it" \
  '.findings | any(.check_id == "DB-05" and .severity == "MEDIUM" and .confidence == "probable" and (.evidence | test("only account/metastore admins")))'
assert "DB-08 HIGH: zero column masks on readable PII; row filter noted; ABAC exemptions flagged as invisible" \
  '.findings | any(.check_id == "DB-08" and .severity == "HIGH" and (.evidence | test("0 column mask")) and (.evidence | test("Row filters exist on app.orders")) and (.evidence | test("exempt principals")))'
assert "DB-09: query history schema not visible -> MEDIUM, probable" \
  '.findings | any(.check_id == "DB-09" and .severity == "MEDIUM" and .confidence == "probable" and (.evidence | test("system.query")))'
assert "DB-ID-01 CRITICAL: human user, 2 groups (1 nested), owns a table, and MANAGE on schema app via analysts" \
  '.findings | any(.check_id == "DB-ID-01" and .severity == "CRITICAL" and (.evidence | test("is a USER")) and (.evidence | test("member of 2 group")) and (.evidence | test("1 through nesting: all-data-readers")) and (.evidence | test("holds MANAGE on SCHEMA app \\(via group analysts\\)")))'
assert "DB-07 HIGH: catalog-level SELECT via all-data-readers and schema-level via analysts are indirect paths" \
  '.findings | any(.check_id == "DB-07" and .severity == "HIGH" and (.evidence | test("CATALOG analytics:SELECT via group all-data-readers")) and (.evidence | test("SCHEMA app:SELECT via group analysts")))'
assert "DB-10 CRITICAL: WRITE FILES via a group; READ VOLUME direct on a volume and cascading from the catalog grant" \
  '.findings | any(.check_id == "DB-10" and .severity == "CRITICAL" and (.evidence | test("raw_exports:WRITE FILES \\(via group analysts\\)")) and (.evidence | test("VOLUME analytics.app.uploads:READ VOLUME")) and (.evidence | test("CATALOG analytics:READ VOLUME \\(via group all-data-readers; cascades")))'
assert "DB-07 includes the MANAGE path" '.findings | any(.check_id == "DB-07" and (.evidence | test("SCHEMA app:MANAGE via group analysts")))'
# casefold: a mixed-case --role still matches lowercase INFORMATION_SCHEMA grantees
python3 skills/db-access-audit/scripts/eval_grants.py --dialect databricks --recorded "$DBX" --role AI-Agent@Example.Invalid --principal-confirmed --emit-json "$TMP/out-case.json"
if jq -e '.findings | any(.check_id == "DB-01")' "$TMP/out-case.json" >/dev/null; then echo "OK: grantee matching is case-insensitive"; else echo "FAIL: mixed-case role produced a clean result"; fail=1; fi
# invisible view definitions -> DB-04 becomes UNKNOWN, never "no masked layer"
DBXV="$TMP/dbx-views"; mkdir -p "$DBXV"; cp "$DBX"/*.csv "$DBXV"/; printf 'catalog,table_schema,table_name,table_type,definition_visible,has_masking_signal\nanalytics,curated,customers_v,VIEW,false,false\n' > "$DBXV/masked_views.csv"
python3 skills/db-access-audit/scripts/eval_grants.py --dialect databricks --recorded "$DBXV" --role ai-agent@example.invalid --principal-confirmed --emit-json "$TMP/out-views.json"
if jq -e '([.findings[] | select(.check_id == "DB-04")] | length == 0) and (.unknowns | any(.check_id == "DB-06" and (.reason | test("DB-04 not assessed")) and (.reason | test("curated.customers_v"))))' "$TMP/out-views.json" >/dev/null; then echo "OK: invisible view definition -> DB-04 UNKNOWN"; else echo "FAIL: invisible view definition treated as unmasked"; fail=1; fi
assert "the INFORMATION_SCHEMA own-grants precondition is stated as a DB-06 unknown, always" \
  '.unknowns | any(.check_id == "DB-06" and (.reason | test("only its own grants")))'
assert "plan_inputs present with principal_kind user, groups, raw tables, planner_supported false" \
  '(.plan_inputs.principal_kind == "user") and (.plan_inputs.groups == ["all-data-readers","analysts"]) and (.plan_inputs.raw_tables | length == 2) and (.plan_inputs.planner_supported == false)'
assert "every databricks finding carries citations and a fingerprint; no value-like strings" \
  '([.findings[] | (.citations | length > 0) and (.fingerprint | length > 0)] | all) and ([tostring | test("password|secret=")] == [false])'
# a service-principal identity that is in no group and holds only view SELECT -> no DB-ID-01, no DB-07
DBXSP="$TMP/dbx-sp"; mkdir -p "$DBXSP"; cp "$DBX"/*.csv "$DBXSP"/; printf 'name,directGroup\n' > "$DBXSP/identity.csv"
python3 skills/db-access-audit/scripts/eval_grants.py --dialect databricks --recorded "$DBXSP" \
  --role 3f1c2b9e-7d4a-4c1e-9b2f-0a6d8e5f4c21 --principal-confirmed --emit-json "$TMP/out2.json"
if jq -e '([.findings[] | select(.check_id == "DB-ID-01" or .check_id == "DB-01" or .check_id == "DB-07" or .check_id == "DB-10" or .check_id == "DB-03")] | length == 0) and (.plan_inputs.principal_kind == "service_principal") and (.findings | any(.check_id == "DB-02" and .severity == "LOW" and (.evidence | test("app.orders \\(direct; not exploitable yet: missing USE SCHEMA app\\)"))))' "$TMP/out2.json" >/dev/null; then echo "OK: a UUID principal in no group: service principal, no identity/write/indirect/external findings; its SELECT without USE SCHEMA is a LOW latent grant"; else echo "FAIL: service principal identity / latent grant"; fail=1; fi
# missing and malformed recorded files fail closed
DBXMISS="$TMP/dbx-missing"; mkdir -p "$DBXMISS"; cp "$DBX"/grants.csv "$DBXMISS"/; printf 'wrong,header\n' > "$DBXMISS/pii_columns.csv"
python3 skills/db-access-audit/scripts/eval_grants.py --dialect databricks --recorded "$DBXMISS" --role ai-agent@example.invalid --principal-confirmed --emit-json "$TMP/out3.json"
assert_file() { if jq -e "$2" "$3" >/dev/null; then echo "OK: $1"; else echo "FAIL: $1"; echo "     (expression: $2)"; fail=1; fi; }
assert_file "databricks: missing files -> one DB-06 per missing query naming the capture command; malformed header -> DB-06; no DB-03/DB-08/DB-ID-01/DB-10 fabricated" \
  '([.unknowns[] | select(.check_id == "DB-06" and (.reason | test("csv. missing")))] | length == 5) and (.unknowns | any(.reason | test("unexpected header"))) and (.unknowns | any(.action | test("dbsqlcli --table-format csv"))) and ([.findings[] | select(.check_id == "DB-03" or .check_id == "DB-08" or .check_id == "DB-ID-01" or .check_id == "DB-10" or .check_id == "DB-04" or .check_id == "DB-05")] | length == 0)' "$TMP/out3.json"
if python3 skills/db-access-audit/scripts/eval_grants.py --dialect databricks --role x --principal-confirmed >/dev/null 2>&1; then echo "FAIL: --dialect databricks without --recorded accepted"; fail=1; else echo "OK: --dialect databricks requires --recorded"; fi
if out="$(python3 skills/safe-db-access/scripts/plan.py --audit "$TMP/out.json" 2>&1 >/dev/null)"; then echo "FAIL: planner rendered for databricks"; fail=1; elif echo "$out" | grep -q "no reviewed templates exist for dialect 'databricks'"; then echo "OK: planner refuses databricks plainly (no templates yet)"; else echo "FAIL: planner refusal wording"; fail=1; fi

step "db-access-audit redshift pack (v0.8): recorded SVV CSVs -> module verdicts"
RS="tests/fixtures/redshift"
python3 skills/db-access-audit/scripts/eval_grants.py --dialect redshift --recorded "$RS" \
  --role ai_agent --principal-confirmed --ignore-dir "$RS" --emit-json "$TMP/out.json"
assert "DB-01 CRITICAL: direct INSERT/UPDATE on app.customers, and ownership of app.scratch_exports counts as write authority" \
  '.findings | any(.check_id == "DB-01" and .severity == "CRITICAL" and (.evidence | test("app.customers:INSERT \\(direct\\)")) and (.evidence | test("app.customers:UPDATE")) and (.evidence | test("Owns 1 relation\\(s\\): app.scratch_exports")))'
assert "DB-02 HIGH: direct SELECT, SELECT via role reporting (transitive), via group bi_users, via PUBLIC, and scoped TABLES via role analyst" \
  '.findings | any(.check_id == "DB-02" and .severity == "HIGH" and (.evidence | test("app.customers \\(direct\\)")) and (.evidence | test("app.customers \\(via role reporting\\)")) and (.evidence | test("app.orders \\(via group bi_users\\)")) and (.evidence | test("app.orders \\(via PUBLIC\\)")) and (.evidence | test("Scoped SELECT on every current and future table in: schema app \\(via role analyst\\)")))'
assert "DB-02: lake.events via role analyst is effective (analyst holds USAGE on lake); column-level SELECT on hr.employees(ssn) is a read path with no relation grant" \
  '.findings | any(.check_id == "DB-02" and (.evidence | test("lake.events \\(via role analyst\\)")) and (.evidence | test("Column-level SELECT: hr.employees\\(salary\\) \\(direct\\), hr.employees\\(ssn\\) \\(direct\\)")))'
assert "DB-03: Restricted HIGH includes the column-granted hr.employees.ssn; Confidential MEDIUM includes hr.employees.salary" \
  '(.findings | any(.check_id == "DB-03" and .severity == "HIGH" and (.evidence | test("app.customers.ssn")) and (.evidence | test("hr.employees.ssn")))) and (.findings | any(.check_id == "DB-03" and .severity == "MEDIUM" and (.evidence | test("full_name")) and (.evidence | test("hr.employees.salary"))))'
assert "DB-04 absent: a masked view exists (customer_masked_v)" '[.findings[] | select(.check_id == "DB-04")] | length == 0'
assert "DB-05 MEDIUM: enable_user_activity_logging = false" \
  '.findings | any(.check_id == "DB-05" and .severity == "MEDIUM" and (.evidence | test("enable_user_activity_logging = false")))'
assert "DB-08 HIGH: the hr-only email mask does nothing for the agent, the PUBLIC full_name mask covers full_name (OUTPUT columns, JSON array form); ssn/card_number/email/hr.* unprotected; RLS noted" \
  '.findings | any(.check_id == "DB-08" and .severity == "HIGH" and (.evidence | test("2 masking attachment")) and (.evidence | test("app.customers.email")) and (.evidence | test("app.customers.full_name") | not) and (.evidence | test("hr.employees.ssn")) and (.evidence | test("RLS is attached on app.orders")))'
assert "DB-09 MEDIUM/probable: export invisible from SQL, own-rows visibility, truncation" \
  '.findings | any(.check_id == "DB-09" and .confidence == "probable" and (.evidence | test("describe-logging-status")) and (.evidence | test("own rows")))'
assert "DB-ID-01 HIGH: password auth (no IAM: prefix), 2 transitive roles (analyst, reporting), group bi_users, owns scratch_exports; not superuser" \
  '.findings | any(.check_id == "DB-ID-01" and .severity == "HIGH" and (.evidence | test("database password")) and (.evidence | test("holds 2 role\\(s\\) transitively: analyst, reporting")) and (.evidence | test("member of 1 group\\(s\\): bi_users")) and (.evidence | test("owns 1 relation")) and (.evidence | test("SUPERUSER") | not))'
assert "DB-07 HIGH: role reporting and the scoped TABLES grant reach the PII table; group/PUBLIC paths to the non-PII orders table are not counted" \
  '.findings | any(.check_id == "DB-07" and .severity == "HIGH" and (.evidence | test("app.customers:SELECT via role reporting")) and (.evidence | test("schema app:SELECT on TABLES via role analyst")) and (.evidence | test("bi_users") | not))'
assert "DB-10 CRITICAL: UNLOAD on the default IAM role via role analyst, COPY via PUBLIC, Spectrum schema lake usable; bucket-level IAM/S3 authorization stays a DB-06" \
  '(.findings | any(.check_id == "DB-10" and .severity == "CRITICAL" and (.evidence | test("UNLOAD with default-aws-iam-role via role analyst")) and (.evidence | test("COPY with default-aws-iam-role via PUBLIC")) and (.evidence | test("lake \\(data_catalog\\):USAGE via role analyst")))) and (.unknowns | any(.check_id == "DB-06" and (.reason | test("IAM/S3 policy"))))'
assert "precondition DB-06 always present; plan_inputs carries roles, groups, iam_auth false, auditor superuser (grants complete), owned relation" \
  '(.unknowns | any(.reason | test("sys:secadmin"))) and (.plan_inputs.roles == ["analyst","reporting"]) and (.plan_inputs.groups == ["bi_users"]) and (.plan_inputs.iam_auth == false) and (.plan_inputs.auditor.secadmin == true) and (.plan_inputs.auditor.grants_partial == false) and (.plan_inputs.owned[0].table == "scratch_exports") and (.plan_inputs.planner_supported == false)'
assert "superuser capture: no 'partial' DB-06" '[.unknowns[] | select(.reason | test("did not run as a superuser"))] | length == 0'
assert "every redshift finding carries citations and a fingerprint" '[.findings[] | (.citations | length > 0) and (.fingerprint | length > 0)] | all'
# non-secadmin capture with an empty policy file -> DB-08 UNKNOWN, not "no policies"
RSNS="$TMP/rs-nonsec"; mkdir -p "$RSNS"; cp "$RS"/*.csv "$RSNS"/
printf 'kind,table_schema,table_name,grantee,grantee_type,output_columns,input_columns,policy_name,detail\n' > "$RSNS/policy_attachment.csv"
grep -v '^auditor,' "$RS/identity.csv" > "$RSNS/identity.csv"; printf 'auditor,user,reguser\nauditor,usesuper,false\n' >> "$RSNS/identity.csv"
sed -i.bak 's/^auditor_is_superuser,true/auditor_is_superuser,false/' "$RSNS/audit_logging.csv" && rm -f "$RSNS/audit_logging.csv.bak"
printf 'table_schema,table_name,has_masking_signal\n' > "$RSNS/masked_views.csv"
python3 skills/db-access-audit/scripts/eval_grants.py --dialect redshift --recorded "$RSNS" --role ai_agent --principal-confirmed --emit-json "$TMP/out-ns.json"
if jq -e '([.findings[] | select(.check_id == "DB-08" or .check_id == "DB-04")] | length == 0) and (.unknowns | any(.check_id == "DB-06" and (.reason | test("neither a superuser nor sys:secadmin")))) and (.unknowns | any(.check_id == "DB-06" and (.reason | test("DB-04 not assessed")))) and (.unknowns | any(.check_id == "DB-06" and (.reason | test("did not run as a superuser")))) and (.plan_inputs.auditor.grants_partial == true)' "$TMP/out-ns.json" >/dev/null; then echo "OK: non-superuser capture -> DB-08 and DB-04 UNKNOWN, grants declared partial"; else echo "FAIL: non-superuser capture not fail-closed"; fail=1; fi
# non-superuser capture with NO grant rows for the agent -> not a clean result
RSNG="$TMP/rs-nogranted"; mkdir -p "$RSNG"; cp "$RSNS"/*.csv "$RSNG"/
for f in grants schema_grants database_grants column_grants; do head -1 "$RS/$f.csv" > "$RSNG/$f.csv"; done
printf 'schema_name,relation_name,relation_type,owner\n' > "$RSNG/ownership.csv"
python3 skills/db-access-audit/scripts/eval_grants.py --dialect redshift --recorded "$RSNG" --role ai_agent --principal-confirmed --emit-json "$TMP/out-ng.json"
if jq -e '([.findings[] | select(.check_id == "DB-01" or .check_id == "DB-02" or .check_id == "DB-03")] | length == 0) and (.unknowns | any(.check_id == "DB-06" and (.reason | test("not a clean result"))))' "$TMP/out-ng.json" >/dev/null; then echo "OK: empty grants below superuser -> explicit 'not a clean result' DB-06"; else echo "FAIL: partial empty grants passed as clean"; fail=1; fi
# case-sensitive identifiers: a mask on "c" must not cover "C"
RSCS="$TMP/rs-case"; mkdir -p "$RSCS"; cp "$RS"/*.csv "$RSCS"/
sed -i.bak 's/^enable_case_sensitive_identifier,false/enable_case_sensitive_identifier,true/' "$RSCS/audit_logging.csv" && rm -f "$RSCS/audit_logging.csv.bak"
printf 'app,customers,Full_Name,character varying,Confidential\n' >> "$RSCS/pii_columns.csv"
python3 skills/db-access-audit/scripts/eval_grants.py --dialect redshift --recorded "$RSCS" --role ai_agent --principal-confirmed --emit-json "$TMP/out-case.json"
if jq -e '.findings | any(.check_id == "DB-08" and (.evidence | test("app.customers.Full_Name")) and (.evidence | test("app.customers.full_name") | not))' "$TMP/out-case.json" >/dev/null; then echo "OK: with case-sensitive identifiers the PUBLIC mask on full_name does not cover Full_Name"; else echo "FAIL: case-sensitive identifier handling"; fail=1; fi
# database-scoped TABLES grant -> broad read path
RSDB="$TMP/rs-dbscope"; mkdir -p "$RSDB"; cp "$RS"/*.csv "$RSDB"/
printf 'dev,SELECT,TABLES,bi_users,group,f\n' >> "$RSDB/database_grants.csv"
python3 skills/db-access-audit/scripts/eval_grants.py --dialect redshift --recorded "$RSDB" --role ai_agent --principal-confirmed --emit-json "$TMP/out-db.json"
if jq -e '(.findings | any(.check_id == "DB-02" and (.evidence | test("database dev — every table in every schema \\(via group bi_users\\)")))) and (.findings | any(.check_id == "DB-07" and (.evidence | test("database dev:SELECT on TABLES via group bi_users"))))' "$TMP/out-db.json" >/dev/null; then echo "OK: database-scoped TABLES grant is a broad DB-02 and an indirect DB-07 path"; else echo "FAIL: database-scoped grant handling"; fail=1; fi
# latent grant: SELECT without schema USAGE -> LOW, excluded from DB-03
RSL="$TMP/rs-latent"; mkdir -p "$RSL"; cp "$RS"/*.csv "$RSL"/
grep -v '^app,USAGE,SCHEMA,ai_agent' "$RS/schema_grants.csv" | grep -v '^app,SELECT,TABLES,analyst' > "$RSL/schema_grants.csv"
grep -v ',reporting,role,' "$RS/grants.csv" | grep -v ',bi_users,group,' | grep -v ',public,public,' > "$RSL/grants.csv"
head -1 "$RS/column_grants.csv" > "$RSL/column_grants.csv"; head -1 "$RS/ownership.csv" > "$RSL/ownership.csv"
python3 skills/db-access-audit/scripts/eval_grants.py --dialect redshift --recorded "$RSL" --role ai_agent --principal-confirmed --emit-json "$TMP/out-latent.json"
if jq -e '(.findings | any(.check_id == "DB-02" and (.evidence | test("app.customers \\(direct; not exploitable yet: no USAGE on schema app\\)")))) and ([.findings[] | select(.check_id == "DB-03")] | length == 0)' "$TMP/out-latent.json" >/dev/null; then echo "OK: SELECT without schema USAGE is reported as latent and is not PII exposure"; else echo "FAIL: latent grant handling"; fail=1; fi
# IAM-auth superuser agent
RSS="$TMP/rs-super"; mkdir -p "$RSS"; cp "$RS"/*.csv "$RSS"/
sed -i.bak 's/^attr,usesuper,false/attr,usesuper,true/' "$RSS/identity.csv" && rm -f "$RSS/identity.csv.bak"
python3 skills/db-access-audit/scripts/eval_grants.py --dialect redshift --recorded "$RSS" --role ai_agent --principal-confirmed --emit-json "$TMP/out-super.json"
if jq -e '(.findings | any(.check_id == "DB-ID-01" and .severity == "CRITICAL" and (.evidence | test("SUPERUSER")))) and (.findings | any(.check_id == "DB-01" and (.evidence | test("SUPERUSER"))))' "$TMP/out-super.json" >/dev/null; then echo "OK: superuser agent -> DB-ID-01 CRITICAL and DB-01"; else echo "FAIL: superuser handling"; fail=1; fi
if python3 skills/db-access-audit/scripts/eval_grants.py --dialect redshift --role x --principal-confirmed >/dev/null 2>&1; then echo "FAIL: --dialect redshift without --recorded accepted"; fail=1; else echo "OK: --dialect redshift requires --recorded"; fi

step "db-access-audit snowflake pack: script-computed verdicts match expected_findings.md"
# v0.7 carry-over from the v0.4 gate: the audit session's own CURRENT_ROLE() is compared to --role
SFF="tests/fixtures/snowflake"
SF_V04=(--identity "$SFF/identity.txt" --policies "$SFF/policy_references.txt" --audit-quality "$SFF/audit_quality.txt")
python3 skills/db-access-audit/scripts/eval_grants.py --dialect snowflake \
  --grants tests/fixtures/snowflake/grants.txt --pii tests/fixtures/snowflake/pii_columns.txt \
  --views tests/fixtures/snowflake/masked_views.txt --settings tests/fixtures/snowflake/audit_logging.txt "${SF_V04[@]}" \
  --role AI_AGENT --principal-confirmed --emit-json "$TMP/out.json"
assert "sf DB-ID-01 HIGH: PERSON user, secondary roles ALL, two roles granted" \
  '.findings | any(.check_id == "DB-ID-01" and .severity == "HIGH" and (.evidence | test("TYPE = PERSON")) and (.evidence | test("ALL")) and (.evidence | test("ANALYST")))'
assert "sf DB-07 HIGH: role inherits ANALYST" \
  '.findings | any(.check_id == "DB-07" and .severity == "HIGH" and (.evidence | test("inherits ANALYST")))'
assert "sf DB-08 HIGH: zero policy references, SSN + CARD_NUMBER unprotected; INFO for dynamic table owner" \
  '(.findings | any(.check_id == "DB-08" and .severity == "HIGH" and (.evidence | test("SSN")) and (.evidence | test("CARD_NUMBER")))) and (.findings | any(.check_id == "DB-08" and .severity == "INFO" and (.evidence | test("SYSADMIN"))))'
assert "sf DB-09 MEDIUM/probable: nobody holds GOVERNANCE_VIEWER, cache reuse on" \
  '.findings | any(.check_id == "DB-09" and .severity == "MEDIUM" and .confidence == "probable" and (.evidence | test("GOVERNANCE_VIEWER")) and (.evidence | test("USE_CACHED_RESULT")))'
assert "sf DB-10 HIGH: USAGE on STAGE" \
  '.findings | any(.check_id == "DB-10" and .severity == "HIGH" and (.evidence | test("STAGE ANALYTICS.APP.EXPORTS")))'
assert "sf v0.4 inputs present: no 'not captured' unknowns" \
  '[.unknowns[] | select(.reason | test("not captured"))] | length == 0'
python3 skills/db-access-audit/scripts/eval_grants.py --dialect snowflake \
  --grants tests/fixtures/snowflake/grants.txt --pii tests/fixtures/snowflake/pii_columns.txt \
  --views tests/fixtures/snowflake/masked_views.txt --settings tests/fixtures/snowflake/audit_logging.txt \
  --role AI_AGENT --principal-confirmed --emit-json "$TMP/out.json"
assert "sf without v0.4 inputs: identity/policy_references/audit_quality UNKNOWN with the GOVERNANCE_VIEWER precondition; no DB-ID-01 / DB-08 HIGH / DB-09 claimed" \
  '([.unknowns[] | select(.reason | test("not captured"))] | length == 3) and (.unknowns | any(.reason | test("GOVERNANCE_VIEWER"))) and ([.findings[].check_id] | (index("DB-ID-01") == null and index("DB-09") == null)) and ([.findings[] | select(.check_id == "DB-08" and .severity != "INFO")] | length == 0)'

step "sf fail-closed on malformed captures: renamed grants column, DESCRIBE USER without TYPE"
sed 's/| granted_on |/| granted_onx|/' tests/fixtures/snowflake/grants.txt > "$TMP/grants-badhdr.txt"
python3 skills/db-access-audit/scripts/eval_grants.py --dialect snowflake \
  --grants "$TMP/grants-badhdr.txt" --pii tests/fixtures/snowflake/pii_columns.txt \
  --views tests/fixtures/snowflake/masked_views.txt --settings tests/fixtures/snowflake/audit_logging.txt "${SF_V04[@]}" \
  --role AI_AGENT --principal-confirmed --emit-json "$TMP/out.json"
assert "renamed granted_on column -> grants DB-06 UNKNOWN; no DB-01/DB-02/DB-07/DB-10 claimed" \
  '(.unknowns | any(.check_id == "DB-06" and (.reason | test("grants")) and (.reason | test("header")))) and ([.findings[].check_id] | (index("DB-01") == null and index("DB-02") == null and index("DB-07") == null and index("DB-10") == null))'
grep -v '^| TYPE ' tests/fixtures/snowflake/identity.txt > "$TMP/identity-notype.txt"
python3 skills/db-access-audit/scripts/eval_grants.py --dialect snowflake \
  --grants tests/fixtures/snowflake/grants.txt --pii tests/fixtures/snowflake/pii_columns.txt \
  --views tests/fixtures/snowflake/masked_views.txt --settings tests/fixtures/snowflake/audit_logging.txt \
  --identity "$TMP/identity-notype.txt" --policies "$SFF/policy_references.txt" --audit-quality "$SFF/audit_quality.txt" \
  --role AI_AGENT --principal-confirmed --emit-json "$TMP/out.json"
assert "DESCRIBE USER without TYPE -> DB-06 UNKNOWN, no DB-ID-01 claimed" \
  '(.unknowns | any(.reason | test("lacks TYPE"))) and ([.findings[].check_id] | index("DB-ID-01") == null)'
sed 's/| DEFAULT_ROLE            | AI_AGENT /| DEFAULT_ROLE            | ANALYST  /' tests/fixtures/snowflake/identity.txt > "$TMP/identity-defrole.txt"
python3 skills/db-access-audit/scripts/eval_grants.py --dialect snowflake \
  --grants tests/fixtures/snowflake/grants.txt --pii tests/fixtures/snowflake/pii_columns.txt \
  --views tests/fixtures/snowflake/masked_views.txt --settings tests/fixtures/snowflake/audit_logging.txt \
  --identity "$TMP/identity-defrole.txt" --policies "$SFF/policy_references.txt" --audit-quality "$SFF/audit_quality.txt" \
  --role AI_AGENT --principal-confirmed --emit-json "$TMP/out.json"
assert "DEFAULT_ROLE different from the audited role is named in DB-ID-01" \
  '.findings | any(.check_id == "DB-ID-01" and (.evidence | test("DEFAULT_ROLE is ANALYST")))'
assert "literal NULL execute_as_user still yields the dynamic-table INFO" \
  '.findings | any(.check_id == "DB-08" and .severity == "INFO" and (.evidence | test("CUSTOMER_MASK_DT")))'
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
