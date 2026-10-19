# 052 — R182K captured maker-argument join

R182J-v2 identifies the two unresolved parameter roots semantically but not concretely: `B` is maker argument 0 (`VMOBJ`) and `c` is maker argument 3 (`PROTO`) of the same VM closure maker. Source callsite census finds no direct static calls, which is expected for values supplied by the captured VM runtime rather than ordinary source-level calls.

R182K joins those semantic roles back to the exact captured dump without assuming that the diagnostic `function_id` is a proto id. It starts from the two composite `(function_id,state_id)` identities present in the 41 R182E-v2 call instances, scans the already-saved frozen evidence for `proto_tid` and `vm_tag`, and requires each state to have a unique proto-table identity candidate. Nested records belonging to a different composite identity are excluded from metadata collection.

The tool then opens the exact `.protos.json` snapshot already selected and SHA-anchored by R182C and constructs the ordinary offline `Program`; it does not call `lift_raw`, `_walk`, or any target code. For each state proto tid it searches captured proto records whose `Program.vm_of(cap)` resolves to the R182J maker location and whose `vm.proto_of(cap).tid` equals the frozen `proto_tid`. If a frozen `vm_tag` is present it is used as an additional exact discriminator. Zero or multiple remaining captures stay unresolved.

For a unique capture join, R182K obtains the captured maker arguments using the same primitives as the devirtualizer: `vm.vmobj_of(cap)` for `B` and `vm.proto_of(cap)` for `c`. It then reads only the constant index paths already recorded by R182I: `B[...]` for `r` and `c[...]` for `K`/`h`. Reads use the captured base tables. A path whose `(tid,key)` is present in `dump.late` is not promoted, and missing/non-table path components fail closed.

A resolved value is classified only as `CAPTURED_BASE_PARAMETER_PATH`. It is not a failure-time value: per-state overlay writes are not replayed, late operands are not replayed, and the captured proto/VM object may have evolved before the failing instruction. Likewise, a successful capture join establishes an offline identity candidate consistent with the frozen proto metadata, not temporal equivalence at the exact instruction.

Run:

```powershell
$env:PYTHONPATH = ".;.\tests"
py -3 -m unittest discover -s tests -p "test_r182k_captured_maker_args.py" -v

py -3 .\tools\analyze_r182k_captured_maker_args.py `
  .\_probe\v15_root27_base_sub_consistency.r182c.json `
  .\_probe\v15_root27_static_path_resolution.r182i.json `
  .\_probe\v15_root27_parameter_provenance.r182j.v2.json `
  .\_probe\v15_root27_source_call_args.r182e.v2.json `
  .\script.txt `
  .\_probe\v15_root27_frontier78_attribution_bigstack `
  .\_probe\v15_frontier78_attribution_bigstack.log `
  --expect-source-sha256 02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443 `
  --json-out .\_probe\v15_root27_captured_maker_args.r182k.json
```

If the separate log path is absent, omit it and keep the confirmed attribution directory. If the accepted source lives elsewhere, replace `.\script.txt` while keeping the SHA gate unchanged.

No lift, attribution, target execution, live fetch, dynamic callgraph inference, overlay replay, late-value replay, candidate bxor evaluation, or semantic change is performed.
