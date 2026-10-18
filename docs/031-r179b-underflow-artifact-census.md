# 031 — R179B existing-artifact underflow census

## Purpose

The accepted frontier checkpoint is still 78 functions / 64 errors / 594
requests. The completed attribution census shows that 49 of the 64 errors are
stack/frame underflows, making underflow the dominant remaining family.

R179B does not rerun the lifter or the protected target. It scans artifacts that
already exist on disk and turns FRAMEFAIL-style evidence into a machine-readable
underflow taxonomy.

## Input handling

`tools/analyze_r179b_underflow_artifacts.py` accepts files or directories and
recursively scans JSON, JSONL, log, Markdown and text artifacts. It understands:

- JSON dictionaries with `kind=below_stack` or `kind=below_stack_store`;
- nested JSON receipts;
- log lines with prefixes such as `[FRAMEFAIL] { ... }`;
- fallback textual errors `read/store below the stack VM's frame (register N)`.

Duplicate evidence for one attributed site is collapsed, preferring the richer
record. An optional `--expect-unique 49` gate refuses to emit a successful
receipt unless the existing artifacts account for all 49 accepted underflow
sites.

## Taxonomy

Each site records read vs store, register, stack base, proto/function/walk/state
coordinates when available, mode/PC/opcode context, jump-register membership,
and whether the existing fact text contains a slot-zero nil hint.

The first split is intentionally simple and evidence-preserving:

- `ZERO_SLOT`: register 0;
- `NEGATIVE_SLOT`: register below 0;
- `UNPARSED`: insufficient register evidence.

No category is treated as safe automatically. In particular, a slot-zero read
is not converted to nil unless the existing devirtualizer proof rules establish
that fact; R179B only reports the evidence already present.

## Usage

```bash
python tools/analyze_r179b_underflow_artifacts.py \
  _probe/v15_root27_frontier78_attribution_bigstack \
  _probe/v15_frontier78_attribution_bigstack.log \
  --expect-unique 49 \
  --json-out _probe/v15_root27_frontier78_underflow_census.json
```

This command performs no lift, no `--all`, no live request, and no protected
execution. The resulting `by_register`, `by_last_op`, `by_proto`, and `sites`
fields decide the next underflow fix from measured evidence rather than by
raising a stack/resource limit.
