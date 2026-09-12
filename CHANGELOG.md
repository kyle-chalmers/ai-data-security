# Changelog

All notable changes to AI Data Security are documented here. This project follows
[Semantic Versioning](https://semver.org). Dates are ISO-8601.

## [0.3.0] — 2026-09-11

The trustworthy-first-run release, shaped by the September 2026 research pass (`docs/research/`).
Every v1 invariant holds: scripts decide and the model narrates, extensions only add detection,
unverifiable states fail closed to UNKNOWN, stdlib-only, and a repo with no config behaves
byte-identically to 0.2.0 except where a check was corrected below.

### Added
- **`/ai-data-security:doctor`** — detects gitleaks, `psql`, `snow`, docker, `claude`, `jq`;
  verifies the citation/check registry and that every evaluator compiles; reports Bash sandbox
  posture; prints a capability matrix naming which checks will be UNKNOWN on this machine.
  Betterleaks (gitleaks' successor) is reported for information only (SPEC design rule 6).
- **`/ai-data-security:quick-check <path>`** — zero flags, three verdict lines (agent-readable
  secrets on disk, deny-rule and sandbox posture, Restricted/Confidential file counts) plus the
  full UNKNOWN list, reusing the existing evaluators with citations and fingerprints intact.
  Says out loud what it does not do (no git history, no warehouse, AC-06 always UNKNOWN); a
  suppressed finding is reported as suppressed, never as a pass; each lane has a 35-second
  budget so the whole run stays under two minutes and a timeout becomes an UNKNOWN. Evaluator
  stderr is never surfaced (fixed error categories only), keeping the evaluators as the
  redaction boundary.
- **AC-07 Bash sandbox posture** — reports when `sandbox.enabled` is not true in user settings or
  the project's `settings.local.json`. Deny rules bind Claude's file tools and recognized Bash
  file commands, not `grep -r` or scripts; only the sandbox enforces the same paths at the OS
  level (Claude Code permissions and sandboxing docs, verified 2026-09-11).
- **SARIF 2.1.0 export** (`scripts/to_sarif.py`; `security-audit … --sarif <file>`): severities map
  to SARIF levels, UNKNOWNs become tool notifications, suppressions carry their reason, every
  result carries the plugin fingerprint. Adds no content and withholds the one unredacted field
  (free-text suppression reasons), so it is as shareable as the report.
- **Citation provenance** — every `reference/citations.yml` entry now records `published`,
  `accessed`, and `status` (`current | superseded | withdrawn`); CI fails a check that cites a
  withdrawn entry. New entries: OWASP Top 10 for Agentic Applications 2026 (ASI02, ASI03), OWASP
  AI Agent Security Cheat Sheet, OWASP MCP Security Cheat Sheet, MCP Security Best Practices
  (dated 2026-07-28), Claude Code permissions and sandboxing docs. DB-01/DB-02 now cite ASI03,
  DB-05 the agent cheat sheet, AC-02 ASI02, AC-03 the MCP cheat sheet.
- **Mission and Vision** in the README, a category-level "what this is not" table (naming
  Anthropic's Claude Security plugin), and `ROADMAP.md`.
- **SPEC amendment** (recorded in `SPEC.md`): a read-only `safe-db-access --plan` may generate the
  remediation recipe as text for human execution. Applying it, and enforcement hooks, remain v2.

### Changed
- **AC-01 matches deny rules by meaning, not spelling.** `Read(.env)`, `Read(**/.env)`,
  `Read(./.env)`, `Read(/.env)`, and `Read(//**/.env)` all satisfy the `.env` requirement; 0.2.0
  compared strings and flagged the stronger any-depth spelling as "missing". The recommendation is
  now the bare-name spelling (a bare filename matches at every depth; `./.env` covers only the
  project root). Regression-locked in `tests/test_matchers.py`. `permeval` tool version 1 → 2.
- The AC-01 subprocess caveat now states the documented boundary precisely (file tools plus
  `cat`/`head`/`tail`/`sed` and redirections; not `grep -r` or scripts) and points at AC-07.
- **Hashing caveat** in `db-access-audit/reference.md` and the four-tier framework: hashed
  identifiers are pseudonymized, not anonymized (NIST SP 800-188 §4.3.2; EDPB Guidelines 01/2025);
  keyed hashing or tokenization with the key outside the AI role's reach is the recommendation,
  and Snowflake's `SERVICE_AGENT` user type (GA 2026-07-23) with `DEFAULT_SECONDARY_ROLES = ()`
  is the identity target.
- The repo's own `.claude/settings.json` and the hardened fixture use the any-depth spellings.

### Fixed
- README "companion content repo" link pointed at this repository; it now points at
  `ai-data-security-demo`.

### Notes
- v0.2.0 (2026-07-15) was merged but never tagged; it is not back-tagged. This release carries
  its notes below.
- OWASP published the LLM Top 10 2026 edition on 2026-08-03. The LLM01/02/06 entries stay
  `current` and cite the 2025 edition until the 2026 renumbering is verified against its PDF.
- MITRE ATLAS technique pages returned 404 to the research fetcher; the three ATLAS entries are
  unchanged and flagged for re-verification before the next release.

## [0.2.0] — 2026-07-15

The adaptability release: the audit learns an organization's vocabulary without giving up a
single v1 invariant — scripts still decide, extensions only ever add detection, unverifiable
states still fail closed, and a repo with no config behaves byte-identically to v0.1.x.

### Added
- **Org profile** — an optional `.ai-data-security.yml` at the audited repo's root
  (JSON-formatted, stdlib-parsed; see `reference/org-config.md`): org-specific PII filename and
  column tokens at either floor, warehouse argument defaults for db-access-audit, and org
  citations appended to matching findings. Extends-only by construction (tokens are validated
  identifiers, so a config line can never inject regex syntax or relax a builtin); a
  present-but-unparseable profile surfaces as a DC-03/DB-06 UNKNOWN — never silently ignored.
- **Snowflake verdicts are script-computed.** `eval_grants.py --dialect snowflake` parses the
  recorded `snow sql` outputs (the same files `--recorded` air-gapped runs use) and computes
  DB-01..DB-05 mechanically — closing the one place where v1 asked the model to apply
  reference.md's interpretation table "mentally". DB-05 stays capped at `probable` (partly
  organizational); malformed recorded output fails closed to DB-06.
- **Marketplace `renames` map** (`datawarden` → `ai-data-security`) so installs under the old
  name migrate instead of breaking (Claude Code ≥ 2.1.193).
- **System-evolution retro** at the end of `/security-audit`: when the audit missed or
  over-flagged, fix the layer — org profile, ignore file, worker skill, or evaluator pattern —
  and file plugin gaps against the plugin repo.

### Changed
- **PII column patterns now match at token boundaries** across `classify_hints.py`, both SQL
  packs, and the four-tier framework: `member_ssn`, `customer_email`, and `email_address`
  match; `emailed_at` does not. The anchored `^…$` patterns missed every prefixed real-world
  column name. The SQL packs also accept `org_restricted`/`org_confidential` regex variables
  (no-op default `(^|_)(__none__)(_|$)`).
- Evaluator tool versions: `classify_hints` and `eval_grants` 1 → 2 (reports show which
  behavior produced a verdict).

### Deferred (noted for a future release)
- Skill trigger evals (skill-creator description-tuning); submission to
  `claude-plugins-community`; the v2 enforcement hooks and safe-db-access IMPLEMENT recipe
  already on the roadmap.

## [0.1.2] — 2026-07-09

### Changed
- **Renamed the plugin `datawarden` → `ai-data-security`** to match the AI Data Security series.
  This changes the repository, the command prefix (`/ai-data-security:<skill>`), the marketplace
  install id (`ai-data-security@ai-data-security`), and the suppression-file convention
  (`.datawarden-ignore` → `.ai-data-security-ignore`). No functional change to any skill. GitHub
  redirects the old repo URL, but existing installs should be reinstalled under the new name:
  ```bash
  claude plugin marketplace remove datawarden 2>/dev/null; claude plugin uninstall datawarden 2>/dev/null
  claude plugin marketplace add kyle-chalmers/ai-data-security
  claude plugin install ai-data-security@ai-data-security
  ```

## [0.1.1] — 2026-07-09

### Fixed
- **data-classification filename precision** — a source-code or docs filename that merely contains
  a sensitive word (`eval_secrets.py`, `payment_service.go`, `security.md`) no longer floors the
  file by name alone; classification of source/doc files is now content-driven. Data/config files
  (`.env`, `credentials.json`, `secrets.yaml`, `.csv`, `.pem`) still floor on their name, and real
  secrets hardcoded inside source are still caught by content scanning.

### Added
- AI Data Security now passes its own `ai-config-audit` — a `.claude/settings.json` ships the secret
  deny-rules AC-01 recommends.
- A repository `.ai-data-security-ignore` triages AI Data Security's own example/fake PII (docs, tests,
  fixtures) so a self-audit returns clean-with-appendix; every entry is visible and reasoned.

## [0.1.0] — 2026-07-09

First public release. Feature-complete v1: audit-only, read-only, every finding cites a standard.

### Skills

- **secrets-scanner** — gitleaks history + working-tree scans, plus the exposure matrix gitleaks
  does not compute (on-disk × in-history × agent-readable × pushed-to-remote); a pushed secret is
  always a rotate-first CRITICAL. Fails closed to UNKNOWN if gitleaks is absent.
- **ai-config-audit** — permission deny/allow rules (flags env-runner wildcard grants), MCP configs
  across Claude/Cursor/Gemini/Codex, plaintext transcripts, and a fail-closed UNKNOWN for the
  consumer retention/training tier (not locally auditable).
- **data-classification** — the 4-tier framework (Public/Internal/Confidential/Restricted, based on
  NIST SP 800-122), deterministic floors (never auto-Public), content validators (Luhn, SSN format);
  reports carry counts and column names, never data values.
- **db-access-audit** — read-only Postgres and Snowflake packs; audits AI-principal write grants,
  raw base-table reads, unmasked PII columns, missing masked views, and missing audit logging.
  Human-gated; supports an air-gapped `--recorded` mode.
- **security-audit** — the ~30-minute orchestrator that merges all of the above into one
  deduplicated, cited report with a severity-ranked Top-5 (rotate-first override).

### Design

- Deterministic stdlib-Python evaluators own every verdict; the model narrates but cannot change
  severity, confidence, or exposure. Severity is capped by confidence; unverifiable checks are
  first-class UNKNOWN (fail-closed). Suppressions (`.ai-data-security-ignore`) always appear in an appendix.
- Verified-only citation registry (OWASP LLM Top 10 2025, MITRE ATLAS, MCP Security Best Practices,
  NIST SP 800-122, NIST AI 600-1).

### Quality

- CI (deterministic, no LLM calls): plugin validation, shellcheck, SQL read-only lint, gitleaks
  self-scan of tree and full history, dockerized Postgres fixture diffs; all GitHub Actions
  SHA-pinned. Fixtures use only vendor-documented or famous-fake values; secret-shaped test data is
  generated at test time, never committed.
- Hardened against two internal adversarial passes (a fresh-context review and an edge-case bug
  hunt): permission-glob precision, uniform fail-closed suppression, a value-leak in classification
  evidence, crash-resistance on hostile inputs, and a regex ReDoS were all fixed and regression-locked.

[0.3.0]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.3.0
[0.1.2]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.1.2
[0.1.1]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.1.1
[0.1.0]: https://github.com/kyle-chalmers/ai-data-security/releases/tag/v0.1.0
