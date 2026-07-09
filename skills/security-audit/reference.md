# security-audit reference

## Merged-report template

```markdown
# AI Data Security Security Audit — <target>
**Date** · **Skills run** (with tool versions) · **DB section**: live / recorded / skipped

## Scorecard
| Section | CRITICAL | HIGH | MEDIUM | LOW | INFO | UNKNOWN |
(one row per phase + a totals row — unknowns are stated in the same breath as findings)

## Top-5 actions
1..5, severity-descending, rotate_first override on top; each names the finding ids it closes
and the single next command/edit to make.

## Phase 0 — Retention tier (manual)     <- AC-06 restated here when present
## Phase 1 — Secrets                     <- secrets-scanner findings
## Phase 2 — AI configuration            <- ai-config-audit findings
## Phase 3 — Data classification         <- classification table + DC findings
## Phase 4 — Database access             <- db-access-audit findings, or the skipped-UNKNOWN

## Suppressed appendix (all skills)
## Disclaimer
```

## Ordering: the one override

Sort actions by severity (CRITICAL > HIGH > MEDIUM > LOW > INFO). Exactly one rule beats
severity: a finding with `rotate_first: true` (a secret that reached a remote) goes first, above
other CRITICALs — rotation is time-critical in a way nothing else in this report is.

## Overlap table (dedupe vs link)

| Pair | Relationship | Action |
|---|---|---|
| SS-03 (`.env` agent-readable) + AC-01 (missing deny rules) | One edit (the deny block) closes both, but root causes differ (secret present vs config absent) | **Link**: "Action N fixes AC-01 and closes SS-03's agent_readable exposure" — keep both findings |
| SS-02 + AC-01 | AC-01 missing-rule list vs a rule already covering the file | Cannot co-occur for the same path; if seen, trust the deterministic evaluators and report both verbatim |
| DC-01 (Restricted file on disk) + SS-0x on the same file | Different lenses (data sensitivity vs credential exposure) | **Link** if same path, never merge |
| DB-03 (PII columns) + DC-01 (PII files) | Different surfaces (warehouse vs repo) | Keep separate; note the shared remediation pattern (masked views) |
| Identical check_id + fingerprint from a re-run | True duplicate | **Merge** (keep one) |

## Skip rules

- No `--db` argument → Phase 4 is a DB-06 UNKNOWN ("skipped — no connection provided"), not an
  omission. The scorecard row still appears.
- A worker skill fails twice → one section-level UNKNOWN with the failure reason; the section
  header still appears. A section silently missing is a report bug, never acceptable.
- Orchestrated `db-access-audit` keeps its own human gate; if the user's `--db` args lack
  `--confirm`, expect the section to stop at the gate and report that state.

## Time budget framing (the "30-minute audit")

Phase 0 ~5 min (manual account check) · Phase 1 ~10 min (scan + read findings) · Phase 2 ~5 min ·
Phase 3 ~5 min · Phase 4 ~5 min. State in the header that phases 1–4 ran automatically and
phase 0 remains manual by nature.
