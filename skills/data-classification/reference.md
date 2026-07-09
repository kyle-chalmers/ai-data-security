# data-classification reference

The tier definitions, detection heuristics, and operating rules live in the shared
[four-tier-framework.md](../../reference/four-tier-framework.md) — this file covers only what is
specific to running the skill.

## Division of labor

`scripts/classify_hints.py` decides: floors (never Public, floor Internal), validator-driven
confidence, DC-01/DC-02 findings, DC-03 unknowns, and suppression. The model decides: final
tiers **upward-only** from the floor, and the one permitted downward move — arguing a file to
Public with an explicit one-line justification.

## DC-03 — unreadable content is an UNKNOWN, not a skip

Any file the script cannot open (permissions, I/O error) produces one DC-03 UNKNOWN naming the
file. Rationale: in a security audit, "we could not look" must be visible — an unreadable file
is exactly where sensitive data hides from scanners.

### Manual fixture (`manual-unreadable-target`)

CI covers this with a generated `chmod 000` file (see `tests/run-fixture-checks.sh`). The manual
procedure for environments where that cannot run:

1. In a scratch copy of any repo, `chmod 000 <some-file>`.
2. Run `/ai-data-security:data-classification <repo>`.
3. Expected: the file appears as a DC-03 UNKNOWN with its path and a fix-permissions action;
   the scorecard's UNKNOWN count is non-zero; the file does NOT appear in the classification
   table as if it had been assessed.

## Suppressing a DC finding

Add the finding's fingerprint (`DC-01:<path>:<tier>`) to `.ai-data-security-ignore` at the target
root, per [finding-format.md](../../reference/finding-format.md). Suppressed findings always
appear in the report appendix; an unparseable `expires=` value counts as expired (fail closed).
