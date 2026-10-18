# 031 — R179B graph-state provenance underflow census

## Schema correction

The accepted checkpoint remains **78 functions / 64 errors / 0 fallbacks / 594 requests**.
The previous adapter incorrectly required a top-level `state_key` on backend/resolved census
records. The completed attribution artifacts instead expose canonical graph identities as
64 `state_id` values in `graph_error_states.json`.

R179B v3 does not synthesize a replacement key. `graph_error_states.json` is the only source
allowed to introduce canonical identity. A graph state may obtain its error in either of two
ways: the graph record itself contains `error`, or a 64-record backend/resolved census carries
an explicit `state_id`/`*_state_id` reference to that graph state. The mapping must be a full
one-to-one bijection over all 64 graph IDs and must reproduce the accepted family census:
49 underflow, 5 symbolic PC/mode, 9 Missing-condition, 1 nil/bxor.

List position and rendered diagnostic tuples such as `(mode, pc, operation, register)` are not
identity and are never used to bridge files. If explicit provenance is absent, the analyzer
fails closed with `refusing order/diagnostic-based identity synthesis`.

Raw, retried, resolved and speculative records are enrichment-only. They can add stack base,
opcode, proto/function/walk or jump-register metadata only when they carry exactly one explicit
reference to a canonical graph `state_id`. They cannot create another census site.

## Regression boundary

The tests are repository-relative: they load `tools/analyze_r179b_underflow_artifacts.py` from
`Path(__file__).resolve().parents[1]`; no `/mnt/data/...` import remains.

Synthetic gates cover a graph-owned 64-state universe, explicit nested `graph_state_id` joins,
263 unrelated raw underflow records that must not increase the 49-site census, missing explicit
provenance, duplicate state references, explicit-state enrichment, and the exact 49/5/9/1 family
split.

## Usage

```powershell
py -3 .\tools\analyze_r179b_underflow_artifacts.py `
  .\_probe\v15_root27_frontier78_attribution_bigstack `
  .\_probe\v15_frontier78_attribution_bigstack.log `
  --expect-unique 49 `
  --json-out .\_probe\v15_root27_frontier78_underflow_census.json
```

No lift rerun, `--all`, live request, protected-target execution, snapshot mutation, positional
join or fabricated identity is performed.
