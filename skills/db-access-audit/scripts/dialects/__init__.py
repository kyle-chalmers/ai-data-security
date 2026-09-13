"""Per-platform evaluators for db-access-audit (v0.7+). Each module exposes

    PACK: dict  query name -> set of required CSV columns (the recorded file is <name>.csv)
    evaluate(role, tables, confidence, unknowns, finding) -> (findings, plan_inputs)

`tables[name]` is a list of row dicts, or None when the file is missing/malformed (the loader has
already appended a DB-06 UNKNOWN). Modules decide; the model narrates. Stdlib only.
"""
