# Codex ("Astra") research run — reconciliation

Run: 2026-09-11, codex-cli 0.146.0, model gpt-5.6-terra (reasoning high), `codex exec -s read-only -c web_search="live"`,
28 live web searches, 37 URLs, 32.7 KB output (`output.md`, prompt in `prompt.md`, log in `stdout.log`). Codex was given the
thesis transcript, README, SPEC, and checks.yml; it was **not** given any Claude-lane output.

Rule: nothing from `output.md` enters the landscape report unless the orchestrating agent (Claude) fetched the source itself
this session. Statuses: **verified** (source fetched, passage supports claim) · **partially supported** · **refuted** ·
**unverifiable** (source not reachable this session) · **misleading / out of scope**.

| # | Codex claim (abridged) | Codex source | Tier Codex gave | Claude fetch | Status | Changed a conclusion? | Disposition |
|---|---|---|---|---|---|---|---|
| C1 | Ranking of five threat framings: data-access boundary first, trifecta second, agent-config supply chain third, NHI lifecycle fourth, relabeled hygiene fifth | inference | — | n/a | inference, adopted as a framing candidate | Yes: landscape §2 opens with competing framings instead of the thesis | adopted, labelled inference |
| C2 | OWASP LLM Top 10 2025 covers prompt injection, sensitive info disclosure, supply chain, excessive agency | genai.owasp.org initiative page | T1 | yes (S14) | partially supported: page now advertises the **2026** edition as latest; item list is in the PDF, not on the page | Yes: quick-win #6 becomes "verify 2026 IDs, then update registry" | kept with correction |
| C3 | Lethal trifecta definition and consequence | Willison 2025-06-16 | T5 | yes (S7) | verified | no | kept |
| C4 | OWASP AI Agent Security Cheat Sheet requires least privilege, untrusted-input handling, human oversight for high-impact actions, structured logging, testing after material changes | cheatsheetseries.owasp.org | T1 | yes (S12) | verified | Yes: new T1 citation candidate for AC checks and for the "test after changes" roadmap item | adopted |
| C5 | OWASP Agentic Skills Top 10 is a distinct layer between LLM reasoning and MCP tooling | owasp.github.io project page | T1 | yes (S13) | verified, but it is a **public-review draft (v1.0-2026, launch Q4 2026)** | Yes: cite as draft only | adopted with "draft" label |
| C6 | NHIs include service accounts, keys, tokens, AI agents; ISPM tracks privileges, rotation, expiry, staleness | Okta ISPM help | T2 | yes (S34) | verified | no | kept |
| C7 | Snowflake DDM is Enterprise+ and rewrites masked columns at every query position | Snowflake docs | T2 | yes (S16) | verified | no | kept |
| C8 | ACCESS_HISTORY is Enterprise+ and does not capture every query shape | Snowflake docs | T2 | yes (S17) | verified | no | kept (roadmap DB-09) |
| C9 | Secondary roles aggregate privileges; can be toggled per session | Snowflake docs ×2 | T2 | yes (S18, S20) | verified; **plus** S19 shows `DEFAULT_SECONDARY_ROLES = ('ALL') \| ()` is a per-user property and `TYPE = SERVICE / SERVICE_AGENT` exist | Yes: DB-ID-01 gains a concrete checkable field (user TYPE, default secondary roles) | adopted, extended |
| C10 | Databricks row filters/column masks are SQL UDFs; ABAC with governed tags is the scalable alternative | Databricks docs | T2 | yes (S22) | verified | no | kept |
| C11 | BigQuery OBJECT_PRIVILEGES omits inherited bindings and needs IAM permissions | Google docs | T2 | yes (S23) | verified verbatim ("does not contain metadata about the inherited access control bindings") | Yes: BigQuery effective-access audit is "partial" in the matrix | adopted |
| C12 | BigQuery RLS documents side channels and feature limits | Google docs | T2 | yes (S24, S25) | verified | no | kept |
| C13 | Redshift DDM system views require superuser / sys:operator / ACCESS SYSTEM TABLE | AWS docs | T2 | yes (S21) | verified | no | kept (auditor-privilege criterion) |
| C14 | Postgres superusers, BYPASSRLS, owners bypass RLS; permissive policies OR together | PostgreSQL 18 docs | T2 | yes (S26) | verified; S27 adds PUBLIC default privileges | Yes: Postgres pack candidates (BYPASSRLS, ownership, PUBLIC) | adopted |
| C15 | Fabric Admin/Member/Contributor bypass OneLake security roles | Microsoft Learn | T2 | yes (S28) | verified verbatim | no | kept |
| C16 | Fabric SQL endpoint delegated mode makes OneLake rules inapplicable | Microsoft Learn | T2 | yes (S29) | verified; **new endpoints default to delegated mode** | Yes: Fabric needs a mode check before any masking verdict | adopted |
| C17 | Lake Formation exposes read-only permission/tag/effective-permission APIs; CloudTrail records GetDataAccess | AWS auth reference; AWS best-practices guide | T2 | yes (S32, S33) | verified | no | kept |
| C18 | DuckDB runs with the process user's privileges; secrets can allow query-driven writes | DuckDB docs | T2 | yes (S30) | verified | no | kept (DuckDB = distinct threat model) |
| C19 | DuckDB persistent secrets are unencrypted on disk | DuckDB docs | T2 | yes (S31) | verified (`~/.duckdb/stored_secrets`) | Yes: secrets-scanner path candidate | adopted |
| C20 | MotherDuck governance surfaces not verified | — | — | not attempted | unverifiable (Codex said so itself) | no | keep UNKNOWN |
| C21 | Platform priority: BigQuery, Databricks, Snowflake depth, dbt, Redshift, Fabric, Lake Formation, DuckDB | inference | — | n/a | inference; Lane 3 to confirm or reorder | pending Lane 3 | hold |
| C22 | Willison Pragmatic Summit talk covers trifecta at ~12:55 | YouTube owmJyKVu5f8 | T3 | metadata only (S41) | partially supported (title/channel verified; timestamp not) | no | listed as "not watched" |
| C23 | "Snowflake – Dynamic Data Masking – Working Session" is a **Snowflake** vendor session | YouTube dPEFRsxFA50 | T2 | metadata (S42) | **refuted**: uploader is an individual (Janardhan Reddy Bandi), so T5 | Yes: drop from vendor-source list | corrected |
| C24 | NIST AI 600-1 final is July 2024; older draft withdrawn | DOI | T1 | yes (S15) | verified (title, July 2024, §2.4 Data Privacy, §2.9 Information Security); "withdrawn draft" note not checked | no | kept |
| C25 | Snyk Agent Scan starts MCP servers with consent, JSON output | GitHub README | T4 | yes (S35) | verified | no | kept (complement; do not invoke by default) |
| C26 | MCPScan outputs terminal/JSON/SARIF | GitHub README | T4 | yes (S36) | verified; **25 stars, 9 commits** — early-stage | Yes: cite as SARIF precedent, not as an established tool | kept with maturity caveat |
| C27 | security-guidance = pattern warnings + LLM diff review + agentic commit review; not data governance | Anthropic README | T2 | yes (S37) | verified | no | kept |
| C28 | Presidio install paths (Docker/pip) | data-privacy-stack docs | T4 | yes (S44) | verified; project is moving from Microsoft to the data-privacy-stack org (repo banner) | no | kept with org note |
| C29 | Macie discovers sensitive data in S3 | AWS docs | T2 | yes (S38) | verified | no | kept |
| C30 | OPA is a general policy engine with CI/CD and gateway integrations | OPA docs | T4 | yes (S39) | verified; no database-authorization use case on the page | no | kept |
| C31 | Entra Workload ID manages identities for apps/services | Microsoft Learn | T2 | yes (S40) | verified | no | kept |
| C32 | NIST SP 800-188 warns hashing/encryption of identifiers carries re-identification risk | NIST PDF | T1 | yes (S10) | verified verbatim §4.3.2: unkeyed hashing "generally does not confer security"; "not recommended" for direct identifiers | **Yes, the largest change**: "hashing as irreversibility" is reframed as pseudonymization with a keyed-hash/tokenization recommendation and a report caveat | adopted |
| C33 | OWASP salt guidance: unique salt defeats precomputation, not brute force of a fast hash | OWASP cheat sheet | T1 | yes (S11) | verified | Yes: caveat text for salted-hash findings | adopted |
| C34 | Claude Code transcripts are plaintext locally; retention is deployment-dependent | Anthropic data-usage | T2 | yes (S9) | verified (30 days default, `cleanupPeriodDays`) | no | kept (AC-05) |
| C35 | Proposed checks DB-ID-01, DB-07..DB-11, AC-07..AC-09, dbt-governance-audit, doctor, citation provenance, `safe-db-access --plan` | inference | — | n/a | design proposals; evaluated in ROADMAP.md against Kyle's four priorities | Yes: several adopted (see ROADMAP) | adopted selectively |
| C36 | `safe-db-access` apply/write mode breaks v1 scope; defer | inference + SPEC | — | SPEC read | supported by SPEC §Out of scope | no (matches plan) | adopted |
| C37 | Mission/vision drafts | inference | — | n/a | see `mission-vision-options.md` Option C | Yes: became Option C | adopted as an option |

## What only Codex found (and Claude kept after verification)
- NIST SP 800-188 §4.3.2 as the primary source against "hashing as irreversibility" (C32).
- OWASP AI Agent Security Cheat Sheet and the draft Agentic Skills Top 10 as T1 citation candidates (C4, C5).
- Fabric's delegated-mode default and the Admin/Member/Contributor bypass (C15, C16).
- DuckDB unencrypted persistent secrets path as a secrets-scanner target (C19).
- BigQuery OBJECT_PRIVILEGES omitting inherited bindings (C11).

## What Codex got wrong or over-tiered
- C23: a community YouTube tutorial labelled as a Snowflake vendor source.
- C2: cited the 2025 LLM Top 10 while the page already advertises 2026 as current.
- C5: presented a public-review draft as a published OWASP standard (fixed with a "draft" label).
- Codex reported the thesis transcript "has no reliable public video ID/timestamps" — true of the file it was given (the ID was withheld to keep the run independent), not of the video.
