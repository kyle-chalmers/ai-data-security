Databricks Unity Catalog pack (v0.7). Every file is a read-only SELECT against
`system.information_schema` (plus one `SHOW GROUPS`). Three placeholders are substituted by the
skill before running, after validation: `${catalog}` (`^[A-Za-z0-9_-]+$`), `${principal}` (the AI
principal: a service principal's applicationId UUID, a user email, or a group name;
`^[A-Za-z0-9_.@+-]+$`), and `${principal_kind}` (`USER` for a user or service principal, `GROUP`
for a group — SHOW GROUPS needs the right keyword). Capture each file as CSV; the SQL is passed to
`dbsqlcli -e` as text, never through a pipe:

    dbsqlcli --table-format csv \
      -e "$(sed -e "s/\${catalog}/<catalog>/g" -e "s/\${principal}/<principal>/g" -e "s/\${principal_kind}/USER|GROUP/g" <file>.sql)" \
      > <tmp>/<file>.csv

Preconditions (stated at the gate): INFORMATION_SCHEMA shows a viewer only its OWN grants unless the
viewer owns the securable or is a metastore admin, and `SHOW GROUPS WITH USER` needs administrator
privileges. Run the capture as the catalog owner or a metastore admin; otherwise the grants are
partial and the audit reports that as UNKNOWN.
