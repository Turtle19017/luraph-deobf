# 046 — R182E-v2 source-AST recovery of omitted bit32.bxor arguments

R181G proved that all 41 call RHS instances bind to `v = Builtin(bit32.bxor)` with `argc = 2`, but the old debug fingerprint did not serialize `args`. Static audit of `_debug_ast_index()` shows that old diagnostics still retained the call node's exact AST `location`. The Luau AST parser also preserves node locations, and the accepted frontier checkpoint has an anchored source SHA-256.

R182E-v1 failed before source recovery because it incorrectly read `right_node` from the R181G instance schema. The preserved debug call fingerprint actually lives in R181F. R182E-v2 reads call location/function fingerprint from R181F, while retaining R181G as the source of normalized `argc=2` and the structured dependency `v = Builtin(bit32.bxor)`.

R182E-v2 therefore reparses the exact original source and recovers the omitted call argument ASTs by strict location identity. It joins R181F and R181G by `instance_index`, verifies `(function_id,state_id,right_type)`, requires exactly 41 call instances, then requires each diagnostic call location to map to exactly one source `AstExprCall` whose function is local `v` and whose source argument count is exactly two.

This is structural source recovery only. The recovered source argument ASTs do not prove runtime argument values; local snapshot timing remains unresolved, and no `bit32.bxor` or final subtraction is evaluated.

Run against the exact accepted source file:

```powershell
$env:PYTHONPATH = ".;.\tests"
py -3 -m unittest discover -s tests -p "test_r182e_source_call_args.py" -v

py -3 .\tools\recover_r182e_source_call_args.py `
  .\_probe\v15_root27_frontier78_local_identity_rhs.r181f.json `
  .\_probe\v15_root27_frontier78_rhs_local_dependencies.r181g.json `
  .\script.txt `
  --expect-source-sha256 02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443 `
  --json-out .\_probe\v15_root27_source_call_args.r182e.v2.json
```

If the exact source lives elsewhere, replace `.\script.txt` with that path. A source SHA mismatch, missing call location, duplicate call location, function-identity mismatch, or argc mismatch fails closed.

No lift, attribution, target execution, live fetch, call evaluation, overlay replay, or semantic change is performed.
