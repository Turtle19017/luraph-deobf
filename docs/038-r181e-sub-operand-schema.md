# 038 — R181E read/Sub operand-schema census

R181D-v2 splits the nine `register=-1, stack_base=1` sites into two store sites with an exact direct local-index link and seven read sites that remain `NO_LINK`. The two exact store links are not evidence for the arithmetic origin of the seven reads.

R181E therefore selects only the seven `operation=read && classification=NO_LINK` sites from the R181D-v2 receipt. It rescans the same frozen artifacts under exact `(function_id,state_id)` identity and requires every selected site to expose at least one `index_ast.op=Sub` instance.

For each Sub AST, R181E inventories the immediate non-metadata child fields, child-node shapes, scalar leaves, and local-container shapes. It does not assume child names such as `lhs/rhs`, does not infer operand order from text, and does not evaluate the subtraction.

The result is schema discovery only. A repeated child layout, scalar value, `K[W]`, or `v(...)` representation does not establish arithmetic origin or a frame-base bug.

```powershell
py -3 .\tools\analyze_r181e_sub_operand_schema.py `
  .\_probe\v15_root27_frontier78_index_local_linkage.r181d.v2.json `
  .\_probe\v15_root27_frontier78_attribution_bigstack `
  .\_probe\v15_frontier78_attribution_bigstack.log `
  --expect-cohort 7 `
  --json-out .\_probe\v15_root27_frontier78_sub_operand_schema.r181e.json
```

No lift rerun, target execution, flag change, snapshot mutation, partial evaluation, or semantic reinterpretation is performed.
