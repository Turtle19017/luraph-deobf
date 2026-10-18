# 050 — R182I exact-declaration static-path resolution

R182H shows that only `r` has a clean single syntactic origin at the recovered call site: `r = B[124]`. `K` and `h` each have one direct assignment but are declared outside the call owner, while `W` and `f` are heavily mutated. R182I therefore focuses on the exact source origins of `r`, `K`, and `h` without attempting to infer `W` or `f`.

The resolver reparses the exact source under the accepted SHA-256 gate and indexes locals by declaration location, never by name alone. For index expressions such as `B[124]`, it identifies the exact declaration of the root local and inventories source assignments to that same declaration at the exact constant path. RHS values are statically bound using the existing Luraph v15 `_bind_value` / `_builtin_chain` machinery, so helper-table entries that resolve to concrete library aliases can become bounded candidates such as `Builtin(bit32.rshift)`.

The same resolver follows `LOCAL_SINGLE_INIT_NO_REASSIGN` and single direct-assignment locals, so the unique RHS origins of `K` and `h` are also tested. Conflicting values at one exact helper-table path fail closed. A same-name helper with a different declaration location is ignored. Mutable direct locals, parameters, cycles, dynamic index paths, unsupported expressions, and unresolved helper-table entries remain unresolved.

Every result is source-static provenance only. A `STATIC_VALUE_CANDIDATE` does not prove the runtime value at the recovered call, does not prove execution order of helper-table writes, does not reconstruct per-state table overlays, and does not authorize replay in R182F by itself.

Run:

```powershell
$env:PYTHONPATH = ".;.\tests"
py -3 -m unittest discover -s tests -p "test_r182i_static_path_resolution.py" -v

py -3 .\tools\analyze_r182i_static_path_resolution.py `
  .\_probe\v15_root27_source_local_provenance.r182h.json `
  .\script.txt `
  --expect-source-sha256 02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443 `
  --json-out .\_probe\v15_root27_static_path_resolution.r182i.json
```

If the accepted source file lives elsewhere, replace `.\script.txt` while keeping the SHA gate unchanged.

No lift, attribution, target execution, live fetch, runtime local-value recovery, overlay replay, candidate call evaluation, or semantic change is performed.
