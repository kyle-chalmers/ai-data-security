-- pii_columns.sql — PII-named columns with tier floor (token-boundary patterns mirror
-- reference/four-tier-framework.md; T-SQL has no regex, so LIKE with token delimiters) and whether
-- the column carries a dynamic data mask (sys.masked_columns). Free-text fields (names, the masking
-- function, which may contain commas and quotes) are CSV-quoted with QUOTENAME(x, '"'), which
-- doubles embedded quotes. Names and types only. Read-only.
SELECT 'schema_name,table_name,column_name,data_type,tier_floor,is_masked,masking_function' AS line
UNION ALL
SELECT CONCAT(QUOTENAME(s.name, '"'), ',', QUOTENAME(t.name, '"'), ',', QUOTENAME(c.name, '"'), ',', ty.name, ',',
  CASE WHEN LOWER('_' + c.name + '_') LIKE '%[_]ssn[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]social[_]security%' OR LOWER('_' + c.name + '_') LIKE '%[_]tax[_]id[_]%'
         OR LOWER('_' + c.name + '_') LIKE '%[_]national[_]id[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]passport%' OR LOWER('_' + c.name + '_') LIKE '%[_]card[_]number[_]%'
         OR LOWER('_' + c.name + '_') LIKE '%[_]pan[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]cvv[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]account[_]number[_]%'
         OR LOWER('_' + c.name + '_') LIKE '%[_]routing[_]number[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]dob[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]birth[_]date[_]%'
         OR LOWER('_' + c.name + '_') LIKE '%[_]date[_]of[_]birth[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]diagnosis[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]medical[_]%'
       THEN 'Restricted' ELSE 'Confidential' END, ',',
  CAST(ISNULL(mc.is_masked, 0) AS varchar(1)), ',', QUOTENAME(ISNULL(mc.masking_function, ''), '"'))
FROM sys.columns c
JOIN sys.tables t ON t.object_id = c.object_id
JOIN sys.schemas s ON s.schema_id = t.schema_id
JOIN sys.types ty ON ty.user_type_id = c.user_type_id
LEFT JOIN sys.masked_columns mc ON mc.object_id = c.object_id AND mc.column_id = c.column_id
WHERE LOWER('_' + c.name + '_') LIKE '%[_]ssn[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]social[_]security%' OR LOWER('_' + c.name + '_') LIKE '%[_]tax[_]id[_]%'
   OR LOWER('_' + c.name + '_') LIKE '%[_]national[_]id[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]passport%' OR LOWER('_' + c.name + '_') LIKE '%[_]card[_]number[_]%'
   OR LOWER('_' + c.name + '_') LIKE '%[_]pan[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]cvv[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]account[_]number[_]%'
   OR LOWER('_' + c.name + '_') LIKE '%[_]routing[_]number[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]dob[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]birth[_]date[_]%'
   OR LOWER('_' + c.name + '_') LIKE '%[_]date[_]of[_]birth[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]diagnosis[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]medical[_]%'
   OR LOWER('_' + c.name + '_') LIKE '%[_]email[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]phone[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]mobile[_]%'
   OR LOWER('_' + c.name + '_') LIKE '%[_]address[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]first[_]name[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]last[_]name[_]%'
   OR LOWER('_' + c.name + '_') LIKE '%[_]full[_]name[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]ip[_]address[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]salary[_]%' OR LOWER('_' + c.name + '_') LIKE '%[_]income[_]%';
