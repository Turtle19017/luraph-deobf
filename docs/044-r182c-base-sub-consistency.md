# 044 — R182C base-value consistency join

R182B recovered concrete base-dump values for the five `LTable#369` keys required by the 95 frozen `K[W]` RHS instances. R182C joins the R181F and R181G instance arrays by the explicit `instance_index` emitted by R181G and verifies `(function_id,state_id,right_type)` before using any value.

For each `AstExprIndexExpr` instance it resolves the structured left-local snapshot from R181F, the structured `W` dependency from R181G, and the selected R182B base value from exactly one `.protos.json` candidate chosen by a unique SHA-256 prefix. It then computes only the hypothetical base expression `left_snapshot - base_table369[W]` and classifies whether that hypothetical result equals `-1`.

`BASE_CONSISTENT_NEG1` is not failure-time proof. The left snapshot may not be live at the exact binary evaluation point, and table reads may observe walk-time overlay writes. `BASE_INCONSISTENT_NEG1` also does not contradict the real observed `-1`; it instead shows that base dump values alone cannot explain that instance under the snapshot-value hypothesis. The 41 `AstExprCall` instances remain `CALL_RHS_UNRESOLVED`.

Run:

```powershell
$env:PYTHONPATH = ".;.\tests"
py -3 -m unittest discover -s tests -p "test_r182c_base_sub_consistency.py" -v

py -3 .\tools\analyze_r182c_base_sub_consistency.py `
  .\_probe\v15_root27_frontier78_local_identity_rhs.r181f.json `
  .\_probe\v15_root27_frontier78_rhs_local_dependencies.r181g.json `
  .\_probe\v15_root27_table369_base.r182b.json `
  --protos-sha-prefix 7792d883 `
  --json-out .\_probe\v15_root27_base_sub_consistency.r182c.json
```

No lift, attribution, overlay replay, call evaluation, target execution, flag change, or semantic reinterpretation is performed.
