# 035 — R181B provenance for the -1/base=1 cohort

R181A measured 19 accepted negative-slot underflows. Nine satisfy both `register == -1`,
`stack_base == 1`, and therefore `register + stack_base == 0`. This repeated affine pattern is
not itself proof of a normalization bug.

R181B is artifact-only. It requires the accepted R181A checkpoint 78/64/0/594 and exactly nine
members in the zero-sum cohort. Existing attribution/debug artifacts may enrich a cohort member
only when an underflow record carries the exact composite `(function_id,state_id)` and the same
negative register. A matching bare state hash from another function is ignored.

The census records raw key/key type, key tree, producer, state_locs, facts and last-op where those
fields already exist. `raw_key == -1` proves only what key reached the failure, not how that key
was derived. No affine pattern, raw literal, or last-op cluster authorizes a semantic change.

Usage:

```powershell
py -3 .\tools\analyze_r181b_negative_slot_provenance.py `
  .\_probe\v15_root27_frontier78_negative_slot_structure.r181a.json `
  .\_probe\v15_root27_frontier78_attribution_bigstack `
  .\_probe\v15_frontier78_attribution_bigstack.log `
  --expect-cohort 9 `
  --json-out .\_probe\v15_root27_frontier78_negative_slot_provenance.r181b.json
```

No lift rerun, target execution, flag change, snapshot mutation, or negative-slot reinterpretation
is performed.
