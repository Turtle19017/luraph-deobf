# 051 — R182J exact parameter provenance census

R182I closes the current static-value lane at parameter boundaries rather than conflicting writes: `r = B[124]` reaches parameter `B` at declaration `2,528520 - 2,528521`, while the single-assignment origins of `K` and `h` reach parameter `c` at declaration `2,528526 - 2,528527`. R182J does not guess those parameter values. It reparses the exact accepted source and identifies each parameter by declaration location.

For every unique parameter boundary found recursively inside the R182I receipt, R182J reports the exact owning `AstExprFunction`, zero-based parameter index, owner argument count, and all statically resolvable direct callsites of that exact function. Function identity is resolved only through direct function expressions or local bindings/aliases whose exact declaration has one static origin and no reassignment. Same-name locals at other declarations are ignored; mutated callee bindings are not trusted.

At each direct static callsite, the tool records the argument AST corresponding to the target parameter. It also notes whether that argument is itself an exact parameter of another function and attempts only a bounded source-static summary for constants or expressions supported by the existing Luraph v15 `_bind_value` machinery. This is a census, not recursive value propagation.

R182J also compares each target parameter against `vmmap.maker_info()` when available. If the exact owning function is one of the detected closure makers, the parameter receives one of the source-level roles `VMOBJ`, `PROTO`, `UPVALS`, or `OTHER` according to the same `proto_index` / `upvals_index` logic already used by the devirtualizer.

The output classes are conservative: `DIRECT_STATIC_CALLS`, `CALLS_WITH_MISSING_ARGUMENT`, `NO_DIRECT_STATIC_CALLS`, or `PARAM_OWNER_NOT_FOUND`. Absence of a direct static call does not prove the function is never invoked; calls through tables, dynamic expressions, returned closures, or mutable aliases may not be statically attributable by this tool. Likewise, an argument AST or maker role does not prove the runtime parameter value.

Run:

```powershell
$env:PYTHONPATH = ".;.\tests"
py -3 -m unittest discover -s tests -p "test_r182j_parameter_provenance.py" -v

py -3 .\tools\analyze_r182j_parameter_provenance.py `
  .\_probe\v15_root27_static_path_resolution.r182i.json `
  .\script.txt `
  --expect-source-sha256 02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443 `
  --json-out .\_probe\v15_root27_parameter_provenance.r182j.json
```

If the exact accepted source lives elsewhere, replace `.\script.txt` and keep the SHA gate unchanged.

No lift, attribution, target execution, live fetch, dynamic callgraph inference, parameter-value promotion, table-overlay replay, candidate bxor evaluation, or semantic change is performed.
