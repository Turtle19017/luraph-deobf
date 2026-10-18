# 047 — R182F frozen candidate evaluation of recovered bxor arguments

R182E-v2 recovered the exact source argument ASTs for all 41 call-RHS instances: `K[W]` and `(r(v(f, h[W], W), 127))`. R182F joins those instances to the corresponding R182C call rows by `instance_index`, verifies `(function_id,state_id)`, reopens the exact `.protos.json` already selected and SHA-anchored by R182C, and then performs a conservative candidate evaluation.

The evaluator resolves locals only from each frozen `local_snapshot_entries`. Integer-like decimal strings are normalized only in numeric contexts such as table indices and bit32 operands. A table lookup is allowed only when the snapshot local is an explicit `LTable#N`, the selected base dump contains that table/key, and the key is not marked `late`. Nested calls are evaluated only when the callee snapshot is an explicit `Builtin(bit32.*)` supported by `core/luasym.py::CONCRETE`, and every argument is concrete numeric data.

For a fully resolved pair of arguments, R182F evaluates the outer `bit32.bxor`, then computes the candidate expression `left_snapshot - bxor_value`. Results are classified as `FULL_CANDIDATE_NEG1`, `FULL_CANDIDATE_OTHER`, or left/argument/builtin failures. Nested unresolved reasons are retained so the first missing dependency remains visible.

All results remain candidate consistency only. Snapshot locals are not proven live at the exact call evaluation point, table reads use base-dump values without per-state overlay replay, and a fully matching candidate does not by itself prove arithmetic origin or a frame-base bug.

Run:

```powershell
$env:PYTHONPATH = ".;.\tests"
py -3 -m unittest discover -s tests -p "test_r182f_bxor_candidates.py" -v

py -3 .\tools\analyze_r182f_bxor_candidates.py `
  .\_probe\v15_root27_base_sub_consistency.r182c.json `
  .\_probe\v15_root27_source_call_args.r182e.v2.json `
  --json-out .\_probe\v15_root27_bxor_candidates.r182f.json
```

No lift, attribution, target execution, live fetch, overlay replay, or semantic change is performed.
