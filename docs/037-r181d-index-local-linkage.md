# 037 — R181D index/local linkage census

R181C established that all nine `register=-1, stack_base=1` sites still have nested frozen evidence. The recurring scalar `-1` appears in register-access keys, key-tree representations, and a local value named `x`; seven sites expose an index AST whose operation is `Sub`.

R181D asks a narrower question: does the `-1` local participate structurally in the index expression, or does it merely coexist in the same frame snapshot?

For each exact `(function_id,state_id)` underflow record, R181D finds local snapshots (`local_values` and `carried_locals`) whose named local equals `-1`, then inspects `index_ast` and `key_tree`.

Classification is fail-closed:

- `AST_EXACT_LOCAL_LINK`: a structured AST field such as `local`, `name`, `identifier`, `var`, etc. explicitly names the same `-1` local.
- `TEXTUAL_LOCAL_LINK`: only AST/key-tree text mentions the local as an identifier token.
- `CO_OCCURRENCE_ONLY`: the local and an index AST coexist without an explicit link.
- `NO_LINK`: no usable link is present.

Even `AST_EXACT_LOCAL_LINK` proves only that the value reaches an index operand. It does not prove the complete arithmetic chain, operand order, frame-base normalization bug, or authorize a semantic change.

```powershell
py -3 .\tools\analyze_r181d_index_local_linkage.py `
  .\_probe\v15_root27_frontier78_negative_slot_provenance.r181b.json `
  .\_probe\v15_root27_frontier78_attribution_bigstack `
  .\_probe\v15_frontier78_attribution_bigstack.log `
  --expect-cohort 9 `
  --json-out .\_probe\v15_root27_frontier78_index_local_linkage.r181d.json
```

No lift rerun, target execution, flag change, snapshot mutation, or semantic reinterpretation is performed.
