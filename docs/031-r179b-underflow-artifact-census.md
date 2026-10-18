# 031 — R179B accepted-final-node underflow census

## Why v1 failed

R179B v1 scanned every underflow-looking artifact and treated raw, resolved,
retried, speculative and final records as peers. On the accepted 78/64/594
artifact set this produced 263 apparent sites. The unchanged `--expect-unique
49` gate correctly rejected that result.

Rendered error text is not node identity either: multiple backend states may
emit the same `(mode, pc, register)` error string.

## v2 membership rule

Only a canonical JSON list of exactly 64 final backend error nodes may create
census membership. Every record must have a unique non-empty `state_key` and
`error`. For checkpoint 78 functions / 64 errors / 0 fallbacks / 594 requests,
the list must also match the accepted family split exactly:

- 49 underflow;
- 5 symbolic PC/mode;
- 9 Missing-condition;
- 1 nil/bxor.

`summary.json` marker-string arrays are deliberately ineligible as the node
universe. Multiple identical 64-node copies are allowed; conflicting universes
fail closed.

Raw/resolved/speculative/debug records are enrichment only. They first match an
accepted node by exact `state_key`; a `(mode, pc, operation, register)` fallback
is used only when it identifies exactly one accepted underflow node. Auxiliary
records can never create another site.

The regression suite includes a production-shaped fixture with 64 canonical
nodes plus 263 raw/speculative underflow records; the census must remain 49.

## Usage

```powershell
py -3 .\tools\analyze_r179b_underflow_artifacts.py `
  .\_probe\v15_root27_frontier78_attribution_bigstack `
  .\_probe\v15_frontier78_attribution_bigstack.log `
  --expect-unique 49 `
  --json-out .\_probe\v15_root27_frontier78_underflow_census.json
```

If the supplied artifacts contain no canonical 64-node list with `state_key +
error`, the tool fails and names that requirement. It does not reconstruct node
identity from rendered strings or weaken the 49 gate. No lift, live request,
`--all`, target execution or snapshot mutation is performed.
