#!/usr/bin/env bash
# Deterministic baseline checks for ai-data-security. Run at session start and before every commit.
# Exits non-zero on any failure. No LLM calls.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
fail=0
step() { echo; echo "==> $1"; }

step "JSON well-formed"
for f in .claude-plugin/plugin.json .claude-plugin/marketplace.json dev/feature_list.json; do
  if ! jq empty "$f" 2>/dev/null; then
    echo "FAIL: $f is not valid JSON"
    fail=1
  fi
done

step "structure: components at plugin root, only manifests inside .claude-plugin/"
[ -d skills ] || { echo "FAIL: skills/ missing at plugin root"; fail=1; }
for d in skills hooks commands agents; do
  if [ -e ".claude-plugin/$d" ]; then
    echo "FAIL: .claude-plugin/$d must not exist (components go at plugin root)"
    fail=1
  fi
done

step "plugin.json contract"
if [ "$(jq -r .name .claude-plugin/plugin.json)" != "ai-data-security" ]; then
  echo "FAIL: plugin.json name must be 'ai-data-security'"
  fail=1
fi
# From 0.1.0 on, a semver version is required (and must NOT also live in the marketplace entry,
# where plugin.json would silently win).
if ! jq -e '.version | test("^[0-9]+\\.[0-9]+\\.[0-9]+")' .claude-plugin/plugin.json >/dev/null; then
  echo "FAIL: plugin.json must carry a semver 'version' (added at 0.1.0)"
  fail=1
fi
if jq -e '.plugins[0] | has("version")' .claude-plugin/marketplace.json >/dev/null; then
  echo "FAIL: marketplace.json plugin entry must NOT set version (plugin.json is the source of truth)"
  fail=1
fi

# Strict from the 0.1.0 release onward: plugin.json now carries a semver version, so --strict
# no longer trips on a missing version field. --strict treats warnings as errors.
step "claude plugin validate --strict"
# This repo is BOTH a plugin and a single-plugin marketplace. A root target ("." ) resolves to
# marketplace.json in preference to plugin.json and never reads skills, so the previous
# "validate ." proved nothing: a garbage SKILL.md passed. There is no flag to force plugin
# mode, so each manifest is named explicitly.
if command -v claude >/dev/null 2>&1; then
  for manifest in .claude-plugin/marketplace.json .claude-plugin/plugin.json; do
    if ! claude plugin validate "$manifest" --strict; then
      echo "FAIL: claude plugin validate $manifest --strict"
      fail=1
    fi
  done

  # Negative control: prove the check above is actually reading skill content. Without this,
  # a regression back to a content-blind target looks identical to a passing gate.
  # Every skill is corrupted in turn: checking only one would let a validator that reads just
  # the first skill pass, and would silently change coverage whenever skills are renamed.
  nc_tmp="$(mktemp -d)" || { echo "FAIL: negative control could not create a temp dir"; fail=1; nc_tmp=""; }
  if [ -n "$nc_tmp" ]; then
    trap 'rm -rf -- "$nc_tmp"' EXIT INT TERM
    if git archive HEAD 2>/dev/null | tar -x -C "$nc_tmp" 2>/dev/null; then
      nc_total=0
      nc_ok=0
      while IFS= read -r nc_victim; do
        nc_total=$((nc_total + 1))
        nc_rel="${nc_victim#"$nc_tmp"/}"
        cp -- "$nc_victim" "$nc_victim.orig" || { echo "FAIL: negative control could not back up $nc_rel"; fail=1; continue; }
        cp -- tests/plugin-validate-negative/broken-SKILL.md "$nc_victim" || { echo "FAIL: negative control could not write $nc_rel"; fail=1; continue; }
        nc_out="$nc_tmp/validate.out"
        if claude plugin validate "$nc_tmp/.claude-plugin/plugin.json" --strict >"$nc_out" 2>&1; then
          echo "FAIL: negative control PASSED for $nc_rel — the gate is not reading that skill"
          fail=1
        elif ! grep -qF "$nc_rel" "$nc_out" || ! grep -qiE 'frontmatter|yaml' "$nc_out"; then
          # A non-zero exit alone is not proof: an unrelated failure would also be non-zero.
          echo "FAIL: negative control failed for the wrong reason on $nc_rel"
          sed "s|$nc_tmp|TMP|g" "$nc_out"
          fail=1
        else
          nc_ok=$((nc_ok + 1))
        fi
        mv -- "$nc_victim.orig" "$nc_victim" || { echo "FAIL: negative control could not restore $nc_rel"; fail=1; }
      done < <(find "$nc_tmp/skills" -type f -name SKILL.md | sort)
      if [ "$nc_total" -eq 0 ]; then
        echo "FAIL: negative control found no SKILL.md to corrupt"
        fail=1
      else
        echo "OK: negative control — $nc_ok/$nc_total skills correctly rejected when corrupted"
      fi
    else
      echo "FAIL: negative control could not export a tree from HEAD"
      fail=1
    fi
    rm -rf -- "$nc_tmp" || { echo "FAIL: negative control could not clean up its temp dir"; fail=1; }
    trap - EXIT INT TERM
  fi
elif [ -n "${ADS_REQUIRE_PLUGIN_GATE:-}" ]; then
  # Set by .github/workflows/ci.yml. Deliberately NOT inferred from $CI: that is set to the
  # string "false" by some runners and by developers locally, and [ -n "false" ] is true, which
  # would block local work. An explicit opt-in variable cannot misfire in either direction.
  echo "FAIL: claude CLI not found but ADS_REQUIRE_PLUGIN_GATE is set — the plugin gate must never be skipped there"
  fail=1
else
  echo "SKIP: claude CLI not found (local only; CI sets ADS_REQUIRE_PLUGIN_GATE and fails if it is missing)"
fi

step "shellcheck on dev/ and tests/ scripts"
if command -v shellcheck >/dev/null 2>&1; then
  while IFS= read -r -d '' f; do
    if ! shellcheck "$f"; then
      echo "FAIL: shellcheck $f"
      fail=1
    fi
  done < <(find dev tests -name '*.sh' -type f -print0 2>/dev/null)
else
  echo "SKIP: shellcheck not found"
fi

step "read-only SQL pack lint (no mutating statements)"
if compgen -G "skills/db-access-audit/sql/*/*.sql" >/dev/null 2>&1; then
  if grep -riEn '^[[:space:]]*(insert|update|delete|drop|alter|create|grant|revoke|truncate|merge|call|copy)\b' \
    skills/db-access-audit/sql/; then
    echo "FAIL: mutating SQL statement found in read-only audit pack"
    fail=1
  else
    echo "OK: SQL packs contain no mutating statements"
  fi
else
  echo "SKIP: no SQL packs yet"
fi

step "fixture checks"
if [ -x tests/run-fixture-checks.sh ]; then
  if ! tests/run-fixture-checks.sh; then
    echo "FAIL: fixture checks"
    fail=1
  fi
else
  echo "SKIP: no fixture checks yet"
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "VALIDATE: PASS"
else
  echo "VALIDATE: FAIL"
  exit 1
fi
