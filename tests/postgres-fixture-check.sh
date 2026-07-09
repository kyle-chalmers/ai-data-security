#!/usr/bin/env bash
# Postgres pack verification for db-access-audit. Spins up a throwaway pinned Postgres in
# docker, loads the misconfigured fixture, runs every read-only pack query THROUGH a
# read-only transaction (PGOPTIONS), diffs outputs against the committed golden CSVs, and
# asserts eval_grants.py verdicts — including the unconfirmed-principal confidence cap.
#
# Usage: tests/postgres-fixture-check.sh [--record]   (--record rewrites expected/ CSVs)
# Skips (exit 0) when docker is unavailable.
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

RECORD=0
[ "${1:-}" = "--record" ] && RECORD=1

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "SKIP: docker unavailable — postgres pack checks skipped"
  exit 0
fi

IMAGE="postgres:16-alpine"
NAME="datawarden-pg-fixture"
PACK="skills/db-access-audit/sql/postgres"
EXPECTED="tests/fixtures/postgres/expected"
OUT="tests/fixtures/generated/postgres-out"
fail=0

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -e POSTGRES_PASSWORD=fixture-placeholder "$IMAGE" >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

# Wait until the REAL server answers a query. pg_isready is not enough: the alpine image
# starts a temporary socket-only server during initdb, shuts it down, then restarts the real
# one — pg_isready can flicker "ready" against the init-phase server, so gate on an actual
# `SELECT 1` succeeding instead (only true once the final server accepts connections).
echo "waiting for postgres to accept queries..."
ready=0
for _ in $(seq 1 120); do
  if docker exec "$NAME" psql -U postgres -d postgres -tAc 'SELECT 1' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "FAIL: postgres never became query-ready; container logs follow"
  docker logs --tail 40 "$NAME" 2>&1 || true
  exit 1
fi

echo "loading fixture schema..."
docker exec -i "$NAME" psql -U postgres -d postgres -q -v ON_ERROR_STOP=1 \
  < tests/fixtures/postgres/init.sql

mkdir -p "$OUT"
for f in "$PACK"/*.sql; do
  name="$(basename "$f" .sql)"
  # default_transaction_read_only=on enforces the pack's read-only promise at the session level.
  docker exec -i -e PGOPTIONS="-c default_transaction_read_only=on" "$NAME" \
    psql -U postgres -d postgres --csv -q -v ON_ERROR_STOP=1 -v ai_role='ai_agent' -f - \
    < "$f" > "$OUT/$name.csv"
  echo "ran $name.sql -> $(wc -l < "$OUT/$name.csv") lines"
done

if [ "$RECORD" -eq 1 ]; then
  mkdir -p "$EXPECTED"
  cp "$OUT"/*.csv "$EXPECTED/"
  echo "RECORDED golden outputs into $EXPECTED/"
else
  for f in "$OUT"/*.csv; do
    name="$(basename "$f")"
    if diff -u "$EXPECTED/$name" "$f"; then
      echo "OK: $name matches golden output"
    else
      echo "FAIL: $name diverges from golden output"
      fail=1
    fi
  done
fi

echo "evaluating verdicts (principal confirmed)..."
EVAL_OUT="$OUT/eval.json"
python3 skills/db-access-audit/scripts/eval_grants.py \
  --grants "$OUT/grants.csv" --pii "$OUT/pii_columns.csv" \
  --views "$OUT/masked_views.csv" --settings "$OUT/audit_logging.csv" \
  --role ai_agent --principal-confirmed --emit-json "$EVAL_OUT"

assert() {
  if jq -e "$2" "$EVAL_OUT" >/dev/null; then echo "OK: $1"; else
    echo "FAIL: $1"; echo "     (expression: $2)"; fail=1; fi
}
assert "DB-01 CRITICAL: write privileges on app tables" \
  '.findings | any(.check_id == "DB-01" and .severity == "CRITICAL" and (.evidence | test("app.customers:INSERT")))'
assert "DB-02 HIGH: SELECT on base tables app.customers + app.orders" \
  '.findings | any(.check_id == "DB-02" and .severity == "HIGH" and (.evidence | test("app.customers")) and (.evidence | test("app.orders")))'
assert "DB-03 HIGH: restricted columns ssn + card_number exposed" \
  '.findings | any(.check_id == "DB-03" and .severity == "HIGH" and (.evidence | test("ssn")) and (.evidence | test("card_number")))'
assert "DB-03 MEDIUM: confidential columns (email, full_name) exposed" \
  '.findings | any(.check_id == "DB-03" and .severity == "MEDIUM" and (.evidence | test("email")))'
assert "DB-04: no masked-view layer" '.findings | any(.check_id == "DB-04")'
assert "DB-05: no audit logging" '.findings | any(.check_id == "DB-05")'
assert "no row data in output (fixture has no data, and no SELECT * anywhere)" \
  '[tostring | test("fixture-placeholder")] == [false]'

echo "evaluating verdicts (principal NOT confirmed -> capped)..."
python3 skills/db-access-audit/scripts/eval_grants.py \
  --grants "$OUT/grants.csv" --pii "$OUT/pii_columns.csv" \
  --views "$OUT/masked_views.csv" --settings "$OUT/audit_logging.csv" \
  --role ai_agent --emit-json "$EVAL_OUT"
assert "unconfirmed principal: every severity capped at MEDIUM" \
  '[.findings[] | .severity == "MEDIUM" or .severity == "LOW" or .severity == "INFO"] | all'
assert "unconfirmed principal: DB-06 unknown present" \
  '.unknowns | any(.check_id == "DB-06")'

echo
if [ "$fail" -eq 0 ]; then echo "POSTGRES PACK: PASS"; else echo "POSTGRES PACK: FAIL"; exit 1; fi
