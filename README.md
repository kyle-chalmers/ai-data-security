# AI Data Security

**Data + AI security audits for data professionals, as a Claude Code plugin.**

## Mission

**AI Data Security shows data professionals what their AI tools can reach across the paths it
audits: deterministic, cited, read-only findings about secrets, sensitive files, agent permissions,
and warehouse access, with every unverifiable state reported as unknown, so they can shrink the
blast radius before an agent touches real data.**

## Vision

**Least-privilege AI access to data becomes something a data team can check in minutes and bring
evidence of to their security team, on the warehouses and agent tools the plugin supports.**

**This is for you if:**

- ✅ you connect Claude Code, Cursor, Codex, or another agent to a warehouse, a repo, or a folder
  of exports, and you are not sure what it can read
- ✅ you own the data but not the security tooling, and want a report that can inform a security
  review (cited, deterministic, no data values in it)
- ✅ you want the audit to say what it could **not** verify instead of quietly passing
- ❌ you need prompt-injection defense, an MCP gateway, DSPM, CIEM, or a SIEM: this sits beside
  those, it does not replace them
- ❌ you want the tool to change grants or rotate credentials for you: the plugin is read-only by
  design; the safe-db-access planner drafts the SQL and a human executes it

---

AI agents read your filesystem, not your `.gitignore`. They connect to your warehouse with
whatever privileges you gave them. AI Data Security audits both sides of that relationship, the AI
tooling's configuration and the data stack it touches, and reports **cited, severity-ranked
findings** with concrete fixes. Read-only by design; nothing mutates anything.

## Start here

```bash
claude plugin marketplace add kyle-chalmers/ai-data-security
claude plugin install ai-data-security@ai-data-security
```

Then, in any project:

```
/ai-data-security:doctor          # what this machine can audit, and what will be UNKNOWN
/ai-data-security:quick-check .   # three verdict lines in about a minute, plus the UNKNOWN list
```

The flagship flow is the **~30-minute security audit**, which runs every skill below and merges
the results into one prioritized report:

```
/ai-data-security:security-audit <path> [--db '--dialect postgres --connection <conninfo> --role <ai-role>']
```

**Requirements:** [gitleaks](https://github.com/gitleaks/gitleaks) (`brew install gitleaks`) for
the secrets scan; the skill fails closed (UNKNOWN, with instructions) rather than substituting a
weaker scanner. `python3` (stdlib only). Optional: `psql` / [Snowflake CLI](https://docs.snowflake.com/en/developer-guide/snowflake-cli)
/ [Databricks SQL CLI](https://docs.databricks.com/aws/en/dev-tools/databricks-sql-cli) / `aws` / `duckdb` for live DB audits; docker only if you run the test suite. `/doctor` checks all of these.

## Skills

| Skill | What it does |
|---|---|
| `/ai-data-security:doctor` | Detects gitleaks, `psql`, `snow`, docker, and the plugin's own registry; prints a capability matrix so you know before running which checks will be UNKNOWN |
| `/ai-data-security:quick-check <path>` | Zero flags: secrets on disk an agent can read, deny-rule and sandbox posture, Restricted-tier file count. Three verdict lines and the UNKNOWN list |
| `/ai-data-security:secrets-scanner <path>` | Secrets on disk **and** in git history (gitleaks), plus the exposure matrix gitleaks doesn't compute: on-disk × in-history × agent-readable × pushed-to-remote |
| `/ai-data-security:ai-config-audit <path>` | Permission deny/allow rules, Bash sandbox posture, MCP configs across Claude, Cursor, Gemini, Codex, VS Code, Windsurf, Cline, Roo, Continue, Copilot CLI, OpenCode; unpinned MCP packages; **write-capable warehouse MCP servers** (Snowflake statement permissions, Postgres MCP access mode, Toolbox tool statements); local credential sinks (DuckDB secrets, warehouse CLI configs, shell history); plaintext transcripts; retention-tier guidance |
| `/ai-data-security:data-classification <path>` | Every file against the 4-tier sensitivity framework, with validated-content evidence (Luhn, SSN format, IBAN mod-97, phone, IPv4). Counts and column names only, never values |
| `/ai-data-security:dbt-governance-audit <dbt-project>` | Static audit of a dbt project's YAML, no warehouse connection: PII-tagged columns and models, exposures that consume them, masking packages in `packages.yml`, and likely-PII columns that carry no tag. A missing tag is never proof of no PII |
| `/ai-data-security:db-access-audit --dialect … --connection … --role … [--user …]` | What your AI principal can actually do in Postgres, Snowflake, Databricks Unity Catalog, Amazon Redshift, Google BigQuery (partial: explicit bindings + project IAM), Microsoft Fabric Warehouse (partial: SQL grants; workspace roles stated as unknown), AWS Lake Formation (partial: explicit grants + IAM policy names), or DuckDB (posture: file mode, process guards, paths out; there are no grants): its **effective identity** (user type, secondary roles, inheritance, ownership), write grants, raw base-table reads and the **indirect paths** to them (inherited, PUBLIC, default privileges), unmasked PII columns and whether a masking control is **attached**, audit-trail blind spots (unreadable, unconfigured, cache-skipped), and **paths outside the database** (stages, server file roles). Human-gated; `--recorded <dir>` air-gapped mode |
| `/ai-data-security:safe-db-access --audit <eval.json>` | **Generate the fix, as text.** From a db-access-audit result: service identity, a key vault for pseudonymization, curated masked views, revoke-raw / grant-curated, audit trail, a validation script run *as the AI role*, and rollback. Postgres and Snowflake. Never connects, never executes, never writes a file; CI applies the Postgres plan to the fixture and proves the audit comes back clean |
| `/ai-data-security:security-audit <path>` | All of the above, merged, deduplicated, Top-5 actions first. `--sarif <file>` exports the merged findings for GitHub Code Scanning |

Every finding cites a standard from a verified-only registry
([reference/citations.yml](reference/citations.yml)): OWASP Top 10 for Agentic Applications 2026,
OWASP LLM Top 10, the OWASP AI Agent and MCP Security cheat sheets, the MCP specification's
security best practices, MITRE ATLAS, NIST SP 800-122, NIST AI 600-1, and the Claude Code docs.
Each entry records when it was published, when it was last verified, and whether it is current.

## The 4-tier framework

**Public / Internal / Confidential / Restricted**, based on NIST SP 800-122's PII
confidentiality impact levels, with explicit AI-tool guidance per tier (Restricted data never
enters an AI context; Confidential requires verified commercial-tier retention; …). Full
definitions, detection heuristics, and operating rules:
[reference/four-tier-framework.md](reference/four-tier-framework.md). Two rules do most of the
work: **the floor is Internal** (nothing is auto-classified Public), and **reports never contain
data values**, so an AI Data Security report is itself Public-tier shareable.

## How verdicts are made (and why you can trust a report)

Deterministic Python scripts (stdlib-only, bundled) compute every verdict: exposure matrices,
severity, confidence. The model narrates and renders; it cannot change a script's verdict.
Severity is **capped by confidence** (`possible ≤ MEDIUM`, `probable ≤ HIGH`, only `confirmed`
reaches CRITICAL), and anything unverifiable is a first-class **UNKNOWN**, stated next to the
finding count, never silently counted as a pass. Suppressions (`.ai-data-security-ignore`) always
appear in an appendix; nothing disappears.

## What AI Data Security is not (use these too)

*Last reviewed: 2026-09. Category-level, because product names churn.*

| Category | Examples | Covers | Relation |
|---|---|---|---|
| Anthropic's own scanners | **Claude Security** (Enterprise beta and Claude Code plugin beta), `security-guidance` | Vulnerabilities in code, including code Claude just wrote | Different scope, same publisher. Neither audits warehouse grants, PII exposure, or the data professional's files. Run them too |
| Coding-agent config and forensic scanners | `agentsec-scanner`, `agent-audit` | Config hygiene and session-log forensics across many agent tools | Closest overlap with `ai-config-audit`, and broader tool coverage. They do not touch warehouses, classification, or the exposure matrix |
| MCP scanners and gateways | `mcp-scan`, Snyk Agent Scan, `MCPScan` | Tool poisoning, rug pulls, credential leaks inside MCP servers | Recommended for MCP internals; this plugin's AC checks stay static and never start unknown servers |
| Secrets engines | gitleaks (dependency; now feature-complete), Betterleaks (its successor), trufflehog (live verification) | Detection in repos and history | gitleaks is the engine this plugin builds the exposure matrix on. Betterleaks is reported by `/doctor` as information until an adapter is approved |
| Prompt-side redaction | `claude-code-privacy-guard`, local privacy proxies | Masking PII in the live prompt | Complementary; protects the conversation, not the disk or warehouse |
| PII discovery and catalogs | Presidio, OpenMetadata, DataHub, Macie | Text/NER PII detection; catalog-wide tagging; cloud DSPM | Complementary; Presidio remains the planned "deep tier" for classification |
| Enforcement and identity | OPA and dbt masking packages; Okta ISPM, Entra Workload ID, CIEM vendors | Enforce policy; govern non-human identities | The remediation and lifecycle layers for what the audit finds |
| Notebook scanning | NB Defense | Secrets/PII in notebooks | Recommended for notebook-heavy repos |
| Red-teaming | garak, promptfoo | Adversarial testing of models | Out of scope |

Among the tools reviewed, none does all four of: warehouse grants for the AI principal,
unmasked-PII-column detection tied to that principal, file classification with counts-never-values,
and the secrets exposure matrix. That combination, delivered locally and free, is this plugin's lane.
The research behind this table is in [docs/research/](docs/research/2026-09-landscape.md).

## Roadmap

See [ROADMAP.md](ROADMAP.md). Shipped: trustworthy first run (v0.3), decision-quality DB audit
(v0.4), agent-config depth and the dbt static audit (v0.5), the human-executed **safe-db-access
planner** (v0.6, a narrow SPEC amendment), Databricks Unity Catalog pack (v0.7), Redshift pack
(v0.8), BigQuery pack (v0.9, partial by design), Fabric Warehouse pack (v0.10, partial by design),
Lake Formation pack (v0.11, partial by design), DuckDB posture pack (v0.12). The v1.x coverage list is complete;
MotherDuck stays UNKNOWN.
Anything that applies changes or enforces at runtime stays a proposal until SPEC v2 is opened.

## Learn more

AI Data Security productizes the "AI Data Security" series by
[Kyle Chalmers | Data + AI](https://www.youtube.com/@kylechalmersdataai) ([kclabs.ai](https://kclabs.ai)).
The companion demo repo with the SQL from the videos is
[ai-data-security-demo](https://github.com/kyle-chalmers/ai-data-security-demo).
The videos cite the plugin; the plugin never depends on the videos.

## Disclaimer

AI Data Security assists a professional's judgment. It is not a compliance certification, a guarantee
of security, or legal advice. Hashed or masked data it reports on remains personal data under
NIST SP 800-188 and the EDPB's pseudonymisation guidance. Audit reports may quote paths and names
from scanned content; treat scanned content as untrusted input (see [SECURITY.md](SECURITY.md)).

## License

[MIT](LICENSE) © Kyle Chalmers
