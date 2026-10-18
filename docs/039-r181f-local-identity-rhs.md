# 039 — R181F local-identity and RHS-shape census

R181E observed 136 frozen Sub AST instances across seven read/NO_LINK sites. Each instance has the same immediate child layout: left is AstExprLocal; right is AstExprIndexExpr (95 instances) or AstExprCall (41 instances).

R181F follows the actual AST fields. It records the complete left and right child nodes, their scalar leaves, immediate right-child schema, and the local snapshot entries from local_values/carried_locals. It tests whether explicit name/id fields in the AstExprLocal node match a declaration in the same frozen record.

The classification is deliberately limited:
- STRUCTURED_MATCH_VALUE_MINUS_ONE: an explicit AST identity field matches a captured local declaration whose recorded value is -1.
- STRUCTURED_MATCH_VALUE_OTHER: an explicit identity match exists, but the captured value is not -1.
- STRUCTURED_MATCH_AMBIGUOUS: the identity points at multiple captured entries with conflicting names/values.
- TEXTUAL_ONLY: a local name occurs only in scalar text, not in a structured identity field.
- NO_STRUCTURED_MATCH: no usable binding was found.

Even a structured match is a candidate binding only: it does not prove that the snapshot value is live at the exact AST evaluation point, and it does not evaluate the right expression or establish the arithmetic origin of the negative index. No semantic change is authorized.

Run against the same frozen evidence, without rerunning lift:

```powershell
$env:PYTHONPATH = ".;.\tests"
py -3 -m unittest discover -s tests -p "test_r181f_local_identity_rhs.py" -v

py -3 .\tools\analyze_r181f_local_identity_rhs.py `
  .\_probe\v15_root27_frontier78_index_local_linkage.r181d.v2.json `
  .\_probe\v15_root27_frontier78_attribution_bigstack `
  .\_probe\v15_frontier78_attribution_bigstack.log `
  --expect-cohort 7 `
  --expect-sub-instances 136 `
  --expect-left-local 136 `
  --expect-right-index 95 `
  --expect-right-call 41 `
  --json-out .\_probe\v15_root27_frontier78_local_identity_rhs.r181f.json
```

No lift rerun, target execution, flag change, snapshot mutation, arithmetic evaluation, or semantic reinterpretation is performed.
