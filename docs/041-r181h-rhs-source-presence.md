# 041 — R181H frozen RHS source-presence census

R181G binds every RHS local dependency uniquely. The 95 index-expression instances use K = LTable#369 and concrete W values; the 41 call instances use v = Builtin(bit32.bxor) with argc = 2. Those bindings identify the missing value sources but do not provide the table contents or call arguments.

R181H derives the required table keys directly from the saved R181G receipt, then scans only the already-saved frozen artifacts. It looks for records that reference LTable#369 (or an explicit table/tid field equal to 369) and inventories content-like fields such as h, entries, items, contents, map, values, or snapshot. Separately, for the exact composite identities of the bit32.bxor call sites, it inventories nested argument-like fields such as args, arguments, argv, operands, call_args, or arg_values.

This is a presence/schema census. A record that references the table does not prove its contents; an entries-like field does not yet prove that every required W key is present; and an args-like field does not yet prove the bit32.bxor inputs. Conversely, zero candidate fields means only that the value source was not captured in the scanned frozen evidence.

Run:

```powershell
$env:PYTHONPATH = ".;.\tests"
py -3 -m unittest discover -s tests -p "test_r181h_rhs_source_presence.py" -v

py -3 .\tools\analyze_r181h_rhs_source_presence.py `
  .\_probe\v15_root27_frontier78_rhs_local_dependencies.r181g.json `
  .\_probe\v15_root27_frontier78_attribution_bigstack `
  .\_probe\v15_frontier78_attribution_bigstack.log `
  --table-ref "LTable#369" `
  --builtin-ref "Builtin(bit32.bxor)" `
  --json-out .\_probe\v15_root27_frontier78_rhs_source_presence.r181h.json
```

No lift rerun, attribution rerun, target execution, flag change, snapshot mutation, table lookup evaluation, call evaluation, or semantic reinterpretation is performed.
