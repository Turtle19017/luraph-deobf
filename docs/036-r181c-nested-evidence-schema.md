# 036 — R181C nested evidence schema census

R181B matched all nine `register=-1, stack_base=1` nodes but its selected top-level extraction found no `raw_key`, producer, state-locs, or last-op fields. Those zero counts do not prove that nested evidence is absent.

R181C therefore rescans the frozen evidence and inventories the complete subtree of every underflow record that matches the exact composite `(function_id, state_id)` and register `-1`. It normalizes list indices in JSON paths and reports all leaf paths, provenance-like candidate paths, nested candidate paths, scalar `-1` paths, value types, site coverage, and short samples.

Candidate path names include `raw_key`, `key_fmt`, `key_type`, `key_tree`, `producer`, `facts`, `state_locs`, `last_op`, `recent_ir`, `jvals`, `jump_regs`, `state_jregs`, `state_packs`, `temp`, `expr`, `index`, `local`, `carry`, `register`, and `stack_base`.

This is schema discovery only. A nested path does not prove arithmetic provenance, and a scalar `-1` does not prove how the underflow key was produced.

```powershell
py -3 .\tools\analyze_r181c_nested_evidence_schema.py `
  .\_probe\v15_root27_frontier78_negative_slot_provenance.r181b.json `
  .\_probe\v15_root27_frontier78_attribution_bigstack `
  .\_probe\v15_frontier78_attribution_bigstack.log `
  --expect-cohort 9 `
  --json-out .\_probe\v15_root27_frontier78_nested_evidence_schema.r181c.json
```

No lift rerun, target execution, flag change, snapshot mutation, or semantic reinterpretation is performed.
