# Codex review of the finished deliverables — dispositions

Run: 2026-09-11, `codex exec -s read-only` (no web search) over `2026-09-landscape.md`, `sources.md`,
`reconciliation.md`, `mission-vision-options.md`, `ROADMAP.md`, `video-idea.md`, `quick-wins.md`, `SPEC.md`.
Raw review follows the disposition table. This is the second Codex gate of the pass; the first reviewed the plan.

| # | Severity | Disposition | What changed |
|---|---|---|---|
| 1 | P0 | **Accepted** | ROADMAP v0.6 planner relabelled "proposed SPEC v2 change; requires explicit approval" with the reasoning: SPEC lists the safe-db-access recipe as out of v1 scope, and text output is still that recipe |
| 2 | P1 | **Accepted** | `/doctor` reports Betterleaks as information only; a Betterleaks adapter is a separate proposed SPEC amendment requiring fixture parity (SPEC design rule 6 names gitleaks primary) |
| 3 | P1 | **Accepted** | Claim 1 scoped to "every connection mode examined … none automatically downscopes"; MCP scope minimization named as the exception |
| 4 | P1 | **Accepted** | Fetched the primary sources: Redshift SVV_ATTACHED_MASKING_POLICY zero-row rule (S84), Redshift audit logging defaults (S85), pgAudit README (S86), PostgreSQL predefined file/program roles (S87). Claim 7, §7, threat map, and roadmap DB-08/09/10 now cite them; remaining Lane-3-only items (RLS attachment view, `IAM:` prefix, `UNLOAD`, read-only GUC limits) are marked "not re-fetched" |
| 5 | P1 | **Accepted** | AC-08 is INFO-level and cites ASI02 (S46) and the OWASP agent cheat sheet (S12); S7 is attributed commentary only; `sources.md` S7 tier note corrected |
| 6 | P1 | **Accepted** | Option A: "exactly" removed, "across the paths it audits", "with every unverifiable state reported as unknown", "a data team can check … and bring evidence of", "the plugin supports"; Option B "limit" → "see what to shrink first"; audience list "a report that can inform a security review"; README patch updated to match |
| 7 | P1 | **Accepted** | Video thesis uses a sourced figure (CSA 74%, S75) instead of "most people's setups fail several"; cold open gated on v0.3 `/quick-check` shipping, with the current-audit fallback and the fixture repo named |
| 8 | P1 | **Accepted** | Title 2 rewritten; beat 5 labels the SQL change as human-applied and states the plugin does not generate it until the v0.6 planner is approved |
| 9 | P1 | **Rejected** | `output.md` exists at `docs/research/codex-run/output.md` in the repo (32,662 bytes) with its `stdout.log` (28 web searches) and `prompt.md`; the review directory received only the deliverables, not the earlier run's artifacts, so the reviewer could not see them. Reconciliation remains checkable against the retained primary output |
| 10 | P2 | **Accepted** | "reversible" → "susceptible to guessing and re-identification" in claim 5 |
| 11 | P2 | **Accepted** | Predicate match/no-match leakage labelled as this report's inference, not a Snowflake-documented bypass |
| 12 | P2 | **Accepted** | §6 header says which rows are author-fetched (`S#`) vs Lane-2 leads; conclusion scoped to "among the tools reviewed" |
| 13 | P2 | **Rejected** | `Read(//**/.env)` is documented in the same Claude Code permissions page (S2) deny-rule table: "any `.env` anywhere on the filesystem". Roadmap AC-01 row now quotes that table so the spelling is traceable |

Overall: 11 of 13 accepted and applied; 2 rejected with evidence. The reviewer's verdict that the hashing correction, survey qualifiers, and IMPLEMENT/hook labels are sound stands.

---

## Raw review

| # | file | location | issue | severity P0/P1/P2 | suggested fix |
|---|---|---|---|---|---|
| 1 | ROADMAP.md | v0.6, line 69 | `safe-db-access --plan` is the v1-out-of-scope IMPLEMENT recipe (roles, grants, masking, validation, rollback), despite emitting text only. It is not labelled “proposed SPEC v2 change.” | P0 | Mark it proposed SPEC v2 change or obtain/specify an approved SPEC amendment first. |
| 2 | ROADMAP.md | v0.3 doctor / landscape §6, lines 29, 201 | Treating Betterleaks as an alternative scanner/adapter changes SPEC’s “gitleaks (primary; detect-or-instruct-install)” rule without a SPEC change. | P1 | Keep Betterleaks a recommendation, or explicitly propose a SPEC amendment and define parity validation. |
| 3 | 2026-09-landscape.md | Claim 1, lines 48–56 | “No protocol layer reduces [connection] privileges” is universal and not supported by S18/S20/S29/S30/S48; S48 expressly describes server-specific token issuance and scope minimization. | P1 | Limit to the documented connection modes: “These examined modes do not automatically downscope the authenticated identity.” |
| 4 | 2026-09-landscape.md / ROADMAP.md | Claim 7; §7 lines 220–221; DB-09/DB-10 | Redshift zero-row semantics, logging-default claim, and Postgres `pgaudit` sink claim are attributed only to “Lane 3,” not a listed source. They drive roadmap checks. | P1 | Add and fetch the AWS/Postgres primary sources, or mark these checks proposed/unverified. |
| 5 | sources.md / ROADMAP.md | S7; AC-08, line 57 | S7 is explicitly T5, then “treated as T3-grade”; AC-08 proposes a finding citing it. That violates the stated tier rule and SPEC’s recognized-standard citation contract. | P1 | Keep S7 as attributed commentary only; support any finding with a T1/T2 source and make the trifecta output informational. |
| 6 | mission-vision-options.md | Option A/B and audience list, lines 28–50, 70–73 | “Exactly what … can reach,” “any data team … in minutes,” “warehouses and agent tools they already use,” and “a security reviewer will accept” exceed the two-pack, UNKNOWN-first audit scope. Option B’s “limit” also implies remediation. | P1 | Scope to “audited paths/configurations” and “supported tools”; say “can help inform review.” Option C is materially sound. |
| 7 | video-idea.md | thesis/cold open, lines 10–13, 25–28 | “Most people’s setups fail several” has no listed evidence; `/quick-check` and its ~50-second runtime are roadmap v0.3, not current functionality. | P1 | Use “this fixture exposes…” and gate the segment on v0.3 shipping; otherwise show the current audit and its actual runtime. |
| 8 | video-idea.md | title 2; beat 5, lines 18, 38 | “I Read Every 2026 AI Agent Security Standard” is refuted by the report’s unopened 2026 LLM PDF. Beat 5 presents DB-ID-01/service-identity remediation as current plugin behavior, though it is roadmap v0.4/v0.6 work. | P1 | Retitle as “What the sources I reviewed say”; identify the SQL change as human-applied/demo or wait for those releases. |
| 9 | reconciliation.md | lines 3–5 | It claims an earlier research `output.md` and corresponding prompt/log support, but `output.md` is absent and the available `prompt.md`/`stdout.log` are this review run. The C1–C37 reconciliation cannot be independently checked. | P1 | Restore immutable prior-run artifacts or state that reconciliation is a summary without retained primary output. |
| 10 | 2026-09-landscape.md | Claim 5, line 95 | “Unsalted hashes are reversible” overstates S10/S11. They support brute-force/dictionary reidentification risk, not reversal of a hash. | P2 | Say “susceptible to guessing and reidentification,” not “reversible.” |
| 11 | 2026-09-landscape.md | Claim 6, lines 98–106 | S16 says masking applies in predicates; it does not itself document Snowflake match/no-match leakage. Calling that a documented bypass overstates the citation. | P2 | Label it an inference or cite a Snowflake-specific demonstration/documentation. |
| 12 | 2026-09-landscape.md | §6, lines 203–211 | The table says “Representative tools (verified)” while several entries are Lane-only/not fetched; “Nothing surveyed does all four” is an unsupported exhaustive claim. | P2 | Mark those rows unverified leads and scope the conclusion to “among the reviewed tools.” |
| 13 | ROADMAP.md | AC-01, line 31 | S2 supports bare-name and `**/.env` semantics, not `Read(//**/.env)` as an equivalent/stronger spelling. | P2 | Remove that spelling until an official syntax source and matcher test establish it. |

Overall verdict: the central hashing correction, survey qualifiers, and explicit v1.0 IMPLEMENT/hook labels are strong.  
Correct: quick-wins is internally consistent; Option C and the video’s honest-close framing avoid “safe/compliant/prevents” claims.  
Block v0.6 as written, repair provenance/source gaps, and make video claims release- and evidence-scoped.