FIXTURE — recorded `sqlcmd -s "," -W -h -1` outputs of the Fabric Warehouse pack against an invented
warehouse `sales_wh`. The AI principal is the Entra service principal `ai-agent-sp` (type E, EXTERNAL),
a member of the fixed role db_datareader (reads everything with no permission row) and of the custom
role `analysts` (SELECT on schema app). It also holds a direct INSERT on app.orders and a DENY SELECT
on app.customers(ssn) — a column DENY that wins over the role's read. Two masked columns exist (email with email(); phone with partial(1,"XXXXXXX",0), a mask whose
function text contains commas and quotes), but role analysts holds UNMASK on phone so that mask does
not bind the agent. On hr.employees the agent has an object-level DENY SELECT but a column-level GRANT
SELECT on salary (the documented column-grant-over-object-deny exception). The agent owns schema
`scratch` and table scratch.exports (CONTROL with no grant row). analysts may EXECUTE
app.usp_customer_lookup (an opaque read path). endpoint_mode.json says the item is a Warehouse.
A view without a masking signal; an RLS policy on app.orders. Values invented.
