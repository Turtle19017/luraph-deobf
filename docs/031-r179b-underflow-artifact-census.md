# 031 — R179B function-local graph-state underflow census

## V4 identity correction

The accepted checkpoint remains **78 functions / 64 errors / 0 fallbacks / 594 requests**.
`graph_error_states.json` contains 64 graph error records, but `state_id` is a function-local
state hash rather than a globally unique ID. In the observed artifact there are 61 unique
raw `state_id` values; three hashes recur in different functions. The explicit pair
`(function_id, state_id)` has 64 unique values.

R179B v4 therefore makes that pair the canonical graph identity. It does not mutate or
rehash `state_id`, manufacture a `state_key`, join by list position, or promote rendered
`(mode, pc, operation, register)` diagnostics into identity.

A graph node obtains its error either directly from its graph record or through a 64-record
backend/resolved census carrying an explicit composite reference. The reference must place a
function-ID field and a state-ID field in the same dictionary object (including a nested
provenance dictionary), resolve to exactly one known graph pair, cover all 64 graph pairs
bijectively, and reproduce the accepted family split: 49 underflow, 5 symbolic PC/mode,
9 Missing-condition, 1 nil/bxor.

A bare `state_id` is deliberately insufficient because the same hash may name distinct states
in different functions. Raw/resolved/speculative records may enrich an accepted site only via
an explicit matching `(function_id, state_id)` pair; they cannot create sites.

## Regression boundary

The repository-relative tests load `tools/analyze_r179b_underflow_artifacts.py` from the repo,
with no `/mnt/data/...` import. Synthetic coverage includes exactly 64 composite graph IDs with
only 61 raw state hashes, nested composite provenance, rejection of bare-state joins, isolation
of equal state hashes across different functions, exact-composite enrichment, and duplicate
composite-ID rejection.

## Usage

```powershell
py -3 .\tools\analyze_r179b_underflow_artifacts.py `
  .\_probe\v15_root27_frontier78_attribution_bigstack `
  .\_probe\v15_frontier78_attribution_bigstack.log `
  --expect-unique 49 `
  --json-out .\_probe\v15_root27_frontier78_underflow_census.v4.json
```

No lift rerun, `--all`, live request, target execution, positional join, diagnostic join, or
snapshot mutation is performed.
