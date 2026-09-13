FIXTURE — recorded AWS CLI JSON of the Lake Formation pack against an invented account 111122223333.
The AI principal is the IAM role `arn:aws:iam::111122223333:role/ai-agent`, which holds SELECT on
`retail.customers` with an EXCLUSION list that misses `email`, unfiltered SELECT + INSERT on
`retail.orders`, and DATA_LOCATION_ACCESS on s3://acme-lake/raw. IAMAllowedPrincipals still has Super
on `retail.legacy_profiles` (IAM alone governs it); default permissions grant IAMAllowedPrincipals on
new tables; one location is in hybrid access mode; the role carries AmazonS3ReadOnlyAccess. A data
cells filter exists on customers but is not granted to the agent. tables.json holds two databases (retail,
marketing) as the documented jq merge produces; opt_ins.json opts a different principal (role/analyst)
into the hybrid location, so IAM still governs the agent there; cloudtrail.json has one multi-region trail.
Values invented; no data.
