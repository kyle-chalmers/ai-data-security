# Mission and Vision options for the ai-data-security plugin

_Drafted 2026-09-11 during the research pass; wording tightened after an independent Codex review
flagged "exactly", "any data team", "prove", and "will accept" as overclaims for a two-pack,
UNKNOWN-first audit. Nothing here is applied to `README.md` or `SPEC.md`; the proposed patches are at
the end for the implementation session._

## Where the words come from

- **Channel mission** (`kc-content-workspace/voice/content-mission.md`): "My content helps data
  professionals use AI successfully within their data stack, with the knowledge and the practical
  skills to build valuable systems and fix what breaks." Values: practicality, intellectual rigor,
  humanity, forward-looking leadership.
- **Sibling pattern** (`ticketwright/README.md`): a bold one-sentence Mission, a bold one-sentence
  Vision, then a ✅/❌ "This is for you if" list.
- **Guardrails from the research** (see `2026-09-landscape.md`): the plugin produces evidence, not
  assurance. SPEC.md keeps UNKNOWN first-class and caps severity by confidence, so the mission may
  not promise "safe", "secure", "compliant", or "protected". The 20c peer review of the Secrets
  Safety brief rejected "keeping credentials safe" for the same reason and settled on "know your
  blast radius and limit it". The independent Codex review of this pass said the same thing in its
  own words: promise "deterministic, read-only evidence about exposure and access boundaries".
- **What it must not claim**: prompt-injection prevention, provider-side retention or routing
  guarantees, continuous monitoring, universal warehouse coverage, compliance certification, or
  that hashed/masked data is non-identifying (NIST SP 800-188 §4.3.2).

## Candidate pairs

### Option A — evidence-first (recommended)

**Mission.** *AI Data Security shows data professionals what their AI tools can reach across the
paths it audits: deterministic, cited, read-only findings about secrets, sensitive files, agent
permissions, and warehouse access, with every unverifiable state reported as unknown, so they can
shrink the blast radius before an agent touches real data.*

**Vision.** *Least-privilege AI access to data becomes something a data team can check in minutes and
bring evidence of to their security team, on the warehouses and agent tools the plugin supports.*

Why it fits: "shows … what … can reach across the paths it audits" is the audit-only contract; "deterministic, cited,
read-only" restates the three v1 invariants; "shrink the blast radius" is the honest promise the
series already uses; "check … and bring evidence" keeps the vision on evidence without promising acceptance, and
"the plugin supports" keeps it honest about two warehouse packs. Nothing in it is falsified by the disconfirmation findings.

### Option B — blast-radius-first

**Mission.** *Help data professionals know the blast radius of every AI agent that touches their
data, and see what to shrink first, with read-only audits whose every finding cites a standard.*

**Vision.** *A data team can connect an AI agent to production data and say, with evidence, what it
can see, what it cannot, and what would change that.*

Why it might win: it leads with the series' phrase and the video's cold-open feeling. Risk: the
earlier draft said "limit", which reads as remediation the v1 plugin does not do; "see what to
shrink first" keeps it on the audit side.

### Option C — the Codex draft, lightly edited

**Mission.** *AI Data Security gives data professionals deterministic, cited, read-only evidence
about how AI tooling can reach sensitive data and credentials.*

**Vision.** *Make least-privilege, governed data access for AI agents easy to inspect and prove
across common data stacks.*

Why it is here: it is the most defensible wording and came from an independent reviewer. Risk: it
reads like a spec, not a promise a viewer remembers.

**Recommendation: Option A**, with Option C's phrase "inspect and prove" available as the README
tagline if A's vision runs long.

## Audience-fit list (for the README, ticketwright pattern)

**This is for you if:**

- ✅ you connect Claude Code, Cursor, Codex, or another agent to a warehouse, a repo, or a folder
  of exports, and you are not sure what it can read
- ✅ your team owns the data but not the security tooling, and you want a report that can inform a
  security review (cited, deterministic, no data values in it)
- ✅ you want the audit to tell you what it could **not** verify instead of quietly passing
- ❌ you need prompt-injection defense, an MCP gateway, DSPM, CIEM, or a SIEM: this sits beside
  those, it does not replace them
- ❌ you want the tool to change grants or rotate credentials for you: v1 is read-only by design,
  and the roadmap's remediation planner stays human-executed

## Proposed README patch (not applied)

```diff
 # AI Data Security

-**Data + AI security audits for data professionals, as a Claude Code plugin.**
+**Data + AI security audits for data professionals, as a Claude Code plugin.**
+
+## Mission
+
+**AI Data Security shows data professionals what their AI tools can reach across the paths it
+audits: deterministic, cited, read-only findings about secrets, sensitive files, agent permissions,
+and warehouse access, with every unverifiable state reported as unknown, so they can shrink the
+blast radius before an agent touches real data.**
+
+## Vision
+
+**Least-privilege AI access to data becomes something a data team can check in minutes and bring
+evidence of to their security team, on the warehouses and agent tools the plugin supports.**
+
+**This is for you if:**
+
+- ✅ you connect Claude Code, Cursor, Codex, or another agent to a warehouse, a repo, or exports,
+  and you are not sure what it can read
+- ✅ you own the data but not the security tooling, and want a report that can inform a security review
+- ✅ you want the audit to say what it could **not** verify instead of quietly passing
+- ❌ you need prompt-injection defense, an MCP gateway, DSPM, CIEM, or a SIEM (this sits beside them)
+- ❌ you want the tool to change grants or rotate credentials for you (v1 is read-only by design)
+
+---
```

## Proposed SPEC.md Mission paragraph (not applied; SPEC changes need maintainer approval)

Replace "helps **data professionals** achieve safe interactions between AI and their data" with:

> AI Data Security is an open-source Claude Code plugin that gives **data professionals**
> deterministic, cited, read-only evidence of what their AI tooling can reach, on both sides of the
> AI-to-data boundary. It reports exposure and access boundaries; it does not certify safety, and
> every unverifiable state is reported as UNKNOWN.

Rationale: "safe interactions" is the one phrase in the current SPEC that the evidence rules of this
pass would flag as an overclaim (see Codex review P0 on Phase C).
