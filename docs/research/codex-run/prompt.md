# Independent research task: how should the ai-data-security plugin evolve?

You are an independent researcher with live web search. Work read-only. Write your final answer as a single markdown document (it is captured to a file). Take as long as you need, up to ~20 minutes.

## Files in this directory (read them first)
- `plugin-README.md`, `plugin-SPEC.md`, `plugin-checks.yml` — the current public docs and check registry of `ai-data-security`, an open-source Claude Code plugin (MIT, plugin semver v0.2.0). It is audit-only and read-only: deterministic Python scripts compute every verdict, the model only narrates; every finding cites a standard from a verified-only registry; unverifiable states are first-class UNKNOWN; severity is capped by confidence.
- `thesis-transcript.txt` — auto-transcript of the owner's YouTube video "So AI Can Access Your Database's PII, What to Do?" (Kyle Chalmers | Data + AI, 2026-05-18, 36 min). It proposes three principles for connecting an AI coding agent to a warehouse: schema segregation, hashing as irreversibility (per-row salt), identity selection (per-human AI service user with only an AI_AGENT role). It declares two non-goals: prompt injection and provider-side routing/retention.

The owner is a data engineer/YouTuber. His four improvement priorities, all weighted equally: (1) generate the fix the audit points at (a "safe-db-access" recipe), (2) dead-simple install and first run, (3) broader coverage (more warehouses, more agent tools, dbt), (4) credibility and standards.

## Evidence rules (mandatory)
- Source tiers: T1 standards/regulators (OWASP, NIST, ISO, CIS, CSA); T2 vendor primary documentation (Snowflake, Databricks, Google, AWS, Microsoft, Anthropic, OpenAI docs); T3 peer-reviewed or preprint research and conference talks with published material; T4 tool documentation/READMEs; T5 commentary (blogs, newsletters, marketing, news). A product or platform assertion needs a T1–T4 source. T5 alone never supports a claim.
- Independence means distinct evidence origins; blogs repeating one vendor claim count once.
- Never treat a search snippet or a generated summary as evidence. Open the page. If you cannot open it, mark the claim unverifiable.
- Record publication date and your access date. For videos, give channel, video ID, and timestamp.
- Label inferences as inferences.

## Do this, in order
1. BEFORE treating the thesis as a recommendation: articulate at least 3 competing threat-model framings for "AI agents touching a data professional's stack" (for example: data-access boundary; lethal-trifecta/exfiltration; non-human identity lifecycle; supply chain of agent configs/MCP servers; basic hygiene relabeled). Rank them by what evidence says matters most for this audience, and say where the thesis fits.
2. Research each framing. Also cover: what warehouse platforms (Snowflake, Databricks, BigQuery, Redshift, Postgres, Azure Fabric/SQL Server, AWS Lake Formation, DuckDB/MotherDuck) natively offer for AI-agent governance, and which of those features a least-privileged read-only principal can audit via metadata queries.
3. List researcher videos (YouTube, conference recordings) and articles on this topic that a data professional should know, with what each covers and what it misses.
4. Survey adjacent/competing tools by category (agent-config scanners, MCP scanners/gateways, Anthropic's own security plugin, prompt redactors, secrets tools, PII discovery/DSPM, IAM/CIEM, database activity monitoring, policy-as-code, agent identity products). For each: coverage, install UX, output formats, overlap vs complement with this plugin.
5. Disconfirmation: where do dedicated AI roles, masked views, salted hashing, or read-only grants fail, mislead, or get misconfigured? (hash re-identification, masking bypass, secondary roles, credential sprawl, exfiltration via logs/transcripts, cost/complexity.)
6. Propose new checks or skills for the plugin. Rank each across: security impact, read-only auditability, deterministic implementability, expected false positives/negatives, platform reach, maintenance burden, fit with the SPEC invariants. Say which are within the audit-only scope and which would require a scope change.
7. Explicit non-goals and a "do not build" list, with reasons.
8. Suggest a one-sentence mission and a one-sentence vision for the plugin that do NOT overclaim (no "safe", no compliance certification, no prevention of prompt injection).

## Output schema
Use a table for every evidenced claim with these columns:
`claim | source title | publisher/author | date | URL | tier | supporting passage or timestamp | applies to plugin how | confidence (high/med/low)`
Then prose sections for items 1, 6, 7, 8. Be specific and terse. Do not pad. If web search is unavailable, say so in the first line.
