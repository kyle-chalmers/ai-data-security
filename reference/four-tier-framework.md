# The 4-Tier Data Sensitivity Framework

The shared vocabulary for `data-classification` (files) and `db-access-audit` (warehouse columns).
Based on the PII confidentiality impact levels of NIST SP 800-122 (low / moderate / high, plus its
"publicly releasable" case) — *based on*, not defined by: SP 800-122 defines three FIPS 199 impact
levels; the Public tier operationalizes its Section 3 discussion of PII already cleared for release.

| Tier | Definition | Impact if exposed (SP 800-122 lens) | AI-tool guidance |
|---|---|---|---|
| **Public** | Already published or cleared for publication (docs, marketing, open-source code) | N/A — already releasable | Any AI tool, any plan tier |
| **Internal** | Non-public operational material (runbooks, architecture notes, internal metrics) | Low — limited adverse effect | Commercial-tier AI tools (no consumer training retention); no external sharing surfaces |
| **Confidential** | Personal or business data identifying people or commercial terms (names + emails, customer lists, contracts) | Moderate — serious adverse effect | Commercial tier with verified retention; masked/aggregated forms preferred; never in prompts to consumer-tier tools |
| **Restricted** | Data whose exposure is severe/catastrophic: government identifiers (SSN), payment card numbers, health records, credentials | High | Never enters an AI context. Access via governed views that hash/mask/omit; AI roles must be provably unable to read raw values |

## Operating rules

1. **The floor is Internal.** Automated classification never assigns Public; a human (or the model
   with an explicit, visible justification) may promote a file to Public — misclassifying *down*
   is the dangerous direction.
2. **Validated content beats column names.** A column named `notes` containing validated SSNs is
   Restricted; a column named `ssn` full of NULLs is still Restricted by intent (design signal).
3. **Reports carry paths, column names, and counts — never data values.** A classification report
   must itself be Public-tier shareable.
4. **One validated hit tiers the whole file/table.** Sensitivity does not average out.

## Detection heuristics (deterministic-first)

### Filename / object-name patterns

| Pattern (case-insensitive) | Floor |
|---|---|
| `*customer*`, `*member*`, `*employee*`, `*user*`, `*contact*`, `*lead*` | Confidential |
| `*patient*`, `*medical*`, `*health*`, `*ssn*`, `*tax*`, `*payroll*`, `*card*`, `*payment*` | Restricted |
| `*.env*`, `*credential*`, `*secret*`, `*.pem`, `*.key` | Restricted (route to secrets-scanner) |

### Column-name patterns

Tokens match at underscore/space boundaries, not whole names only: `member_ssn`,
`customer_email`, and `email_address` all match; `emailed_at` does not (`email` is not a
whole token there). Anchored whole-name matching missed every prefixed real-world column.

| Token | Floor |
|---|---|
| `ssn`, `social_security`, `tax_id`, `national_id`, `passport` | Restricted |
| `card_number`, `pan`, `cvv`, `account_number`, `routing_number` | Restricted |
| `dob`, `birth_date`, `date_of_birth`, `medical`, `diagnosis` | Restricted |
| `email`, `phone`, `mobile`, `address`, `first_name`, `last_name`, `full_name`, `ip_address` | Confidential |
| `salary`, `income`, `compensation` | Confidential |

An org profile (`.ai-data-security.yml`, see [org-config.md](org-config.md)) may **add**
org-specific filename and column tokens at either floor; it can never remove a builtin
token or lower a floor.

### Content validators (upgrade confidence, never downgrade)

| Validator | Rule | On success |
|---|---|---|
| SSN format | `\d{3}-\d{2}-\d{4}` with area ∉ {000, 666, 900–999}, group ≠ 00, serial ≠ 0000 | Restricted, confidence `confirmed` |
| Payment card | 13–19 digits passing Luhn | Restricted, confidence `confirmed` |
| Email | RFC-lite `local@domain.tld` | Confidential, confidence `confirmed` |

Pattern-only hits (no validated content) stay confidence `probable`; severity capping in
[finding-format.md](finding-format.md) then applies.
