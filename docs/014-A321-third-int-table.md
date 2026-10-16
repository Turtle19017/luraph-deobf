# 014 — Two post-second scalars, third integer table, and phase-4 boundary

## Correction

The previous parser started the third integer table one field too early.

After the second count-sized table, the source consumes **two** serialized
scalars before the third count-sized table begins.

For verified block #1:

```text
second table end   10201
scalar A           15 hex = 21
scalar B           1f hex = 31
third table start  10203
```

The incorrect earlier boundary treated `0x1f` as the first third-table entry.
That shifted the table end by one byte and incorrectly interpreted the final
third-table byte `0x0f` as the low byte of a u32 phase-4 count.

## Exact source transition

After the second-table loop exits:

```text
495 -> 404 -> 50
```

State 50 reads scalar A. In the observed corpus scalar A is one byte wide and
takes:

```text
50 -> 325 -> 503
```

State 503 then reads the first limb of **scalar B**, not the first table entry.

Scalar-B width paths converge at state 412:

```text
width 1: 503 -> 4   -> 412
width 2: 503 -> 435 -> 327 -> 412
width 3: 503 -> 435 -> 305 -> 116 -> 412
width 4: 503 -> 435 -> 305 -> 372 -> 412
```

Only after scalar B is decoded does state 412 allocate the next two count-sized
tables and create the loop descriptor.

## Third table

State 412 uses the still-live object count as the loop bound:

```text
412
→ 36(T)      loop controller
→ 401(vW)    read first serialized-integer limb
→ ...        1/2/3/4-byte integer decoder
→ 343(Py)    store value[index]
→ 36(T)
```

The layout is therefore:

```text
header
first_int_table[count]
tag215
meta16
meta5
secondary_integer
second_int_table[count]
post_second_scalar_a
post_second_scalar_b
third_int_table[count]
phase4_record_count_u32
...
```

## Correct block #1 checkpoint

```text
count                    4474
second table end         10201
scalar A                 21 / 15
scalar B                 31 / 1f
third table start        10203
third table end          15209
third table encoded size 5006
width histogram          1-byte:3944, 2-byte:529, 4-byte:1
phase4 count bytes       00 00 00 00
phase4 record count      0
phase4 start             15213
```

With the corrected boundary, block #1 phase 4 is empty. This removes the
previous apparent contradiction where an odd tagged u32 would have implied an
enormous inner loop.

## Reproduce

`tools/decode_a321_third_tables.py` is schema v2 and now reports the two
scalars separately.

```bash
python tools/decode_a321_third_tables.py \
  _probe/a321_plaintexts \
  --json _probe/a321_third_tables.v2.json
```

The tool remains fail-closed on runtime size/SHA/head16 and on all previously
verified prefix/table invariants.
