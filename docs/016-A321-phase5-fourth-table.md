# 016 — Phase 5 scalars C/D/E and fourth count-sized table

## Scope

This report continues from the corrected third-table and phase-4 record-stream
boundaries. It deliberately uses a larger semantic batch rather than promoting
one flattened state at a time.

Known layout before this phase:

```text
first_int_table[count]
...
second_int_table[count]
scalar A
scalar B
third_int_table[count]
u32 phase4_record_count
phase4_records[...]
```

After phase 4, source mapping establishes three serialized integers followed by
a fourth table with the original object count:

```text
scalar C
scalar D
scalar E
fourth_int_table[count]
```

## Scalar C

Phase 4 exits through:

```text
407 -> 1 -> 388
```

State 388 begins scalar C. All integer-width branches converge at state 485:

```text
width 1: 388 -> 395 -> 485
width 2: 388 -> 148 -> 498 -> 485
width 3: 388 -> 148 -> 274 -> 105 -> 485
width 4: 388 -> 148 -> 274 -> 65  -> 485
```

## Scalar D

State 485 stores scalar C and immediately begins scalar D. All widths converge
at state 340:

```text
width 1: 485 -> 199 -> 340
width 2: 485 -> 510 -> 511 -> 340
width 3: 485 -> 510 -> 208 -> 326 -> 340
width 4: 485 -> 510 -> 208 -> 122 -> 340
```

## Scalar E

State 340 stores scalar D and begins scalar E. All widths converge at state 129:

```text
width 1: 340 -> 26  -> 129
width 2: 340 -> 230 -> 206 -> 129
width 3: 340 -> 230 -> 441 -> 424 -> 129
width 4: 340 -> 230 -> 441 -> 125 -> 129
```

## Fourth count-sized table

At state 129, scalar E is stored and two new tables are allocated with the
original object count. A loop descriptor is created with that same count as its
bound.

The fourth table loop is:

```text
129 -> 169

169        loop controller
  -> 43    read first serialized-integer limb

width 1: 43 -> 80  -> 475 -> 169
width 2: 43 -> 200 -> 371 -> 475 -> 169
width 3: 43 -> 200 -> 18  -> 120 -> 475 -> 169
width 4: 43 -> 200 -> 18  -> 487 -> 475 -> 169

475        store decoded integer by loop index
169        repeat until exactly count entries are consumed
  -> 361   loop exit
```

## Block #1 checkpoint

Verified block #1:

```text
phase4 record count   0

scalar C              130 / 81 02 / width 2
scalar D               68 / 44    / width 1
scalar E               29 / 1d    / width 1

fourth table start    15217
fourth table end      20931
encoded bytes          5714
entries                4474
widths                 1-byte:3240, 2-byte:1231, 4-byte:3
minimum                0
maximum                404839701
zero entries           60

raw SHA-256
f14a8de2dd31217d2dac7536edc68a58808ba59a195c19dc3c1e0e1840e127e7

values-u64le SHA-256
ee399d3e16043f66b9ff13d3b2e38ed34d43408c476fd9469d14738aadae31d4
```

Only five bytes remain in block #1 after the proven fourth-table boundary:

```text
00 a3 bd 01 6d
```

Those bytes are intentionally not assigned field semantics in this report.
The next source path contains another register-shuffled parser sequence and will
be promoted only after its convergence is proven.

## Offline corpus parser

`tools/decode_a321_phase4_through_fourth_table.py` recomputes the complete
corrected prefix, parses phase-4 records without materializing ranges, decodes
scalars C/D/E through their source-derived paths, and consumes exactly `count`
fourth-table integers.

```bash
python tools/decode_a321_phase4_through_fourth_table.py \
  _probe/a321_plaintexts \
  --json _probe/a321_phase4_through_fourth_table.json
```

The parser verifies each plaintext against the runtime size/SHA/head receipt.
A failure is a format/path divergence and must not be repaired by changing
offsets or counts.
