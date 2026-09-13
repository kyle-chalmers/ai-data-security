FIXTURE — recorded `duckdb -readonly -csv -header` outputs plus a stat line for an invented local file
`analytics.duckdb` sitting in a repo, world-readable (mode 644), opened read-write by the capture,
with httpfs installed, a persistent S3 secret, a MotherDuck attachment, PII columns (incl. a quoted `member ssn` column with a space boundary), and one plain view.
`file.csv` is the stat line plus the `git_ignore` column the recipe appends (`not_ignored`: inside a repo, no
ignore rule). Values invented; no data.
