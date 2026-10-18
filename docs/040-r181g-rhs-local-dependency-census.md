# 040 — R181G RHS local-dependency census

R181F established that all 136 frozen Sub instances have a structured left-local binding, but the captured left snapshot values are 2/3/4/8 rather than -1. The right operand therefore remains the unresolved part of the arithmetic expression. R181E already established two RHS schemas: 95 AstExprIndexExpr nodes with fields expr/index and 41 AstExprCall nodes with fields func/argc.

R181G consumes only the saved R181F JSON. It does not rescan the attribution logs and therefore does not depend on the two historical attribution processes that were later terminated by a server restart.

For every RHS subtree, the analyzer inventories all AstExprLocal dependencies and attempts to bind their explicit local name/id fields to the local_snapshot_entries already saved by R181F. For AstExprIndexExpr it separately reports the node types of expr and index. For AstExprCall it separately reports the func node type, argc histogram, and whether an args field is present.

A structured RHS/local match is dependency evidence only. Snapshot timing is not proven, table indexing is not evaluated, function calls are not evaluated, and the Sub result is not recomputed. No arithmetic-origin or frame-base-bug claim follows from this census.

Run:

```powershell
$env:PYTHONPATH = ".;.\tests"
py -3 -m unittest discover -s tests -p "test_r181g_rhs_local_dependencies.py" -v

py -3 .\tools\analyze_r181g_rhs_local_dependencies.py `
  .\_probe\v15_root27_frontier78_local_identity_rhs.r181f.json `
  --json-out .\_probe\v15_root27_frontier78_rhs_local_dependencies.r181g.json
```

No lift rerun, target execution, attribution rerun, flag change, snapshot mutation, RHS evaluation, or semantic reinterpretation is performed.
