# 048 — R182G cross-record local provenance census

R182F cannot candidate-evaluate the 41 recovered `bit32.bxor` calls because their joined per-instance snapshots contain only `v = Builtin(bit32.bxor)` while `K`, `W`, `f`, `h`, and `r` are missing. R182E-v2, however, recovered the exact source AST for both call arguments, including each `AstExprLocal` name and source declaration location.

R182G returns to the already-saved frozen evidence without rerunning lift or attribution. It groups records strictly by canonical `(function_id,state_id)` for the 41 R182E-v2 call instances and inventories `local_values`, `carried_locals`, and `local_events` across every matching frozen record. For every source local appearing in the recovered argument ASTs it compares frozen evidence against the exact source declaration location when that information is present.

The classification ladder is intentionally conservative:

- `EXACT_DECL_UNIQUE`: one unique value is attached to an entry that itself carries the exact source declaration location.
- `EXACT_DECL_CONFLICT`: exact-declaration entries disagree; no value is chosen.
- `EVENT_PLUS_NAME_UNIQUE`: no entry carries the declaration location directly, but a record contains a `local_event` for the exact declaration and a unique same-name value candidate in that record.
- `EVENT_PLUS_NAME_CONFLICT`: those event-linked same-name candidates disagree.
- `NAME_ONLY_UNIQUE`: the state has one same-name value across scanned records but no exact declaration linkage.
- `NAME_ONLY_CONFLICT`: same-name values disagree.
- `NO_VALUE`: no matching value candidate was captured.

Only `EXACT_DECL_UNIQUE` is direct declaration/value linkage. Even that remains cross-record frozen evidence and is not proven live at the exact call evaluation point. `EVENT_PLUS_NAME_UNIQUE` is weaker correlation and `NAME_ONLY_UNIQUE` is inventory only. R182G does not authorize candidate evaluation or semantic changes.

Run:

```powershell
$env:PYTHONPATH = ".;.\tests"
py -3 -m unittest discover -s tests -p "test_r182g_cross_record_locals.py" -v

py -3 .\tools\analyze_r182g_cross_record_locals.py `
  .\_probe\v15_root27_source_call_args.r182e.v2.json `
  .\_probe\v15_root27_frontier78_attribution_bigstack `
  .\_probe\v15_frontier78_attribution_bigstack.log `
  --json-out .\_probe\v15_root27_cross_record_locals.r182g.json
```

If the separate log path is absent, run with only the confirmed attribution directory. Missing input paths fail closed.

No lift, attribution, target execution, live fetch, table-overlay replay, call evaluation, timing inference, or semantic change is performed.
