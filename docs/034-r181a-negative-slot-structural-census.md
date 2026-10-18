# 034 — R181A negative-slot structural census

R180B closes the R0 lane for frozen evidence: no accepted R0 site has a surviving proof source. R181A therefore measures the remaining 19 negative-slot underflows without changing semantics.

The analyzer consumes the accepted R179B-v4 census and requires checkpoint 78/64/0/594, 64 composite graph identities, and exactly 19 negative-register sites. For each site it records operation, register, stack_base, last_op, jump-register membership, distance below zero, and the affine measurements `register + stack_base` and `register - stack_base` when stack_base is present.

It also reports exact relations such as `register == -stack_base` and `register == 1-stack_base`, plus histograms/dominant values. These are measurements only: even a repeated affine relation does not prove a base-normalization bug and does not authorize a semantic change.

Usage:

```powershell
py -3 .\tools\analyze_r181a_negative_slot_structure.py `
  .\_probe\v15_root27_frontier78_underflow_census.v4.json `
  --expect-negative 19 `
  --json-out .\_probe\v15_root27_frontier78_negative_slot_structure.r181a.json
```

No lift rerun, flag change, target execution, snapshot mutation, or negative-slot reinterpretation is performed.
